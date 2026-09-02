//! APF watchdog: keep an "ICMP echo request to guest → PASS" rule alive in the Wi-Fi
//! firmware's APF program.
//!
//! Why this exists (apf/README.md has the measurements): on this device the Xiaomi
//! vendor part of the APF program drops EVERY inbound IPv4 ICMP echo request
//! (`DROPPED_ICMP_ECHO`, counter 21) regardless of destination — the phone's own address
//! included. pbridge's `fwd-with-offload` already fixes ARP (a guest `/32` on wlan0 makes
//! NetworkStack's ARP-request branch unconditionally PASS) and guest TCP/UDP were never
//! affected, so ICMP echo is the last hole. Inserting `ldw r0,[30]` + one
//! `jeq r0,<guest>,PASS` per guest ahead of that drop restores it, verified end to end.
//!
//! The catch: NetworkStack regenerates and reinstalls the program on Doze, RA, address /
//! LinkProperties, multicast and keepalive changes, which throws the patch away. So this
//! module reacts to a BPF kprobe on the driver's APF vendor-command entry point and
//! redoes the whole thing from whatever program is live at that moment:
//!
//! ```text
//! disable → read work memory → walk/locate/patch → validate → write → read back
//!         → byte-compare → enable
//! ```
//!
//! `enable` runs on every exit path: the driver only permits read/write while the
//! interpreter is disabled, and leaving APF disabled would silently drop the phone's own
//! battery-saving packet filtering.
//!
//! No shelling out, no `lpc_ctl`, no `dumpsys`: [`vendor`] speaks the QCA nl80211 vendor
//! command directly, and the program length is derived from the work memory itself.
//!
//! # The two methods
//!
//! Everything above describes `--apf-method watchdog`, the default, implemented by
//! [`repatch()`]. The alternative is `--apf-method inflight` ([`inflight`]), which ptraces
//! the Wi-Fi HAL and rewrites the program inside its `sendmsg` before the kernel sees it.
//! They are mutually exclusive — running both would double-patch, and each one's
//! "already carries our rules" check would trip over the other's work.
//!
//! | | `watchdog` | `inflight` |
//! |---|---|---|
//! | when | after the install | before the install |
//! | window | debounce + one transaction | none |
//! | proof | firmware readback | tracee-buffer readback |
//! | needs | BPF kprobe | CAP_SYS_PTRACE on `hal_wifi_default` |
//! | addresses | fixed or DHCP-derived | fixed or DHCP-derived |
//! | declined install | repaired late | left unpatched |
//!
//! In DHCP mode the in-flight tracer reads a shared address set that the control-plane actor
//! updates on each validated DHCPACK, so nothing blocks inside the stopped syscall. A lease
//! change additionally runs one [`repatch()`] transaction, which is the only time in-flight
//! mode touches the firmware: without it a new guest would wait for NetworkStack's next
//! install to get its rule.
//!
//! Both share the planner ([`patch::plan_with_arp`]) and the debugbuf derivation
//! ([`program::debugbuf_of`]), so the bytes they produce for a given program are identical.

pub mod inflight;
pub mod patch;
pub mod program;
pub mod setmsg;
pub mod vendor;

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;

pub use program::{ProgramLayout, APF_RAM_BYTES};
pub use vendor::VendorSocket;

/// Outcome of one repatch transaction, for logging and retry policy.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The live program was stock; we patched, wrote and verified it.
    Patched {
        stock_len: usize,
        patched_len: usize,
        guests: usize,
    },
    /// The live program already carries exactly our rules — nothing written.
    AlreadyPatched { len: usize },
}

/// Run the full transaction against `ifindex`. Blocking; called from the core actor
/// (each vendor command is a few ms — the whole thing measured ~42 ms on device).
pub fn repatch(sock: &mut VendorSocket, ifindex: u32, guests: &[Ipv4Addr]) -> Result<Outcome> {
    if guests.is_empty() {
        bail!("apf: no watchdog guests configured");
    }
    sock.apf_disable(ifindex).context("apf disable")?;

    // From here on APF is disabled and MUST be re-enabled. `panic_guard` covers an
    // unwind through this frame (it opens its own socket, since ours is borrowed); the
    // normal and error paths re-enable explicitly below. There is no await point inside
    // the window, so a Tokio shutdown cannot cancel us mid-transaction.
    let panic_guard = PanicEnableGuard {
        ifindex,
        armed: true,
    };
    let result = disabled_window(sock, ifindex, guests);
    std::mem::forget(panic_guard);

    let enabled = sock.apf_enable(ifindex).context("apf enable");
    match (result, enabled) {
        // The transaction outcome wins: a patched-and-verified program with a failed
        // re-enable is still worth reporting as such, but it must not look like success.
        (Ok(_), Err(e)) => Err(e).context("apf: program installed but interpreter left disabled"),
        (Err(e), Ok(())) => Err(e),
        (Err(e), Err(e2)) => {
            log::error!(
                "apf: re-enable ALSO failed: {e2:#} — APF is left DISABLED on ifindex {ifindex}; \
                 the next NetworkStack install re-enables it"
            );
            Err(e)
        }
        (Ok(o), Ok(())) => Ok(o),
    }
}

/// The part that requires the interpreter to be disabled: read the live program, patch
/// it, write it back and prove the firmware took it byte for byte.
fn disabled_window(sock: &mut VendorSocket, ifindex: u32, guests: &[Ipv4Addr]) -> Result<Outcome> {
    let work = sock
        .apf_read(ifindex, APF_RAM_BYTES, 0)
        .context("apf read work memory")?;
    let layout = ProgramLayout::derive(&work).context("apf: cannot trust live program layout")?;
    let stock = &work[..layout.program_len];

    let patched = match patch::plan_with_arp(stock, layout.debugbuf_size, guests)? {
        patch::Plan::AlreadyPatched => {
            return Ok(Outcome::AlreadyPatched {
                len: layout.program_len,
            })
        }
        patch::Plan::Patch(p) => p,
    };

    sock.apf_write(ifindex, &patched, 0)
        .context("apf write patched program")?;
    let back = sock
        .apf_read(ifindex, patched.len(), 0)
        .context("apf read back patched program")?;
    if back.len() < patched.len() {
        bail!(
            "apf readback short: got {} of {} bytes",
            back.len(),
            patched.len()
        );
    }
    if back[..patched.len()] != patched[..] {
        let at = back.iter().zip(patched.iter()).position(|(a, b)| a != b);
        bail!(
            "apf readback differs from what we wrote (first difference at byte {at:?}) — \
             firmware did not take the program"
        );
    }
    Ok(Outcome::Patched {
        stock_len: layout.program_len,
        patched_len: patched.len(),
        guests: guests.len(),
    })
}

/// Last-resort re-enable if the disabled window unwinds. Opens a fresh socket because
/// the caller's is mutably borrowed by the frame being unwound.
struct PanicEnableGuard {
    ifindex: u32,
    armed: bool,
}

impl Drop for PanicEnableGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let r = VendorSocket::open().and_then(|mut s| s.apf_enable(self.ifindex));
        match r {
            Ok(()) => log::error!("apf: panic in the disabled window; interpreter re-enabled"),
            Err(e) => log::error!("apf: panic in the disabled window AND re-enable failed: {e:#}"),
        }
    }
}
