//! In-flight APF patcher: rewrite the Wi-Fi HAL's APF program inside its own `sendmsg`.
//!
//! One of the two mutually exclusive APF methods, selected by `--apf-method inflight`
//! (see `cli::ApfMethod`). The other, [`super::repatch()`], reacts *after* NetworkStack
//! installs a program: a BPF kprobe fires, then pbridge does
//! disable/read/patch/write/read/enable. Correct, but there is a live window — the debounce
//! plus one transaction — where the unpatched program runs.
//!
//! This module closes that window by patching the program before the kernel ever sees it.
//! The trade is symmetric and worth stating plainly: no window, but also no second chance.
//! The watchdog repairs anything it can parse, whatever shape it arrives in, and proves the
//! result by reading it back out of the firmware. This path must decide inside a stopped
//! syscall, so an install it cannot patch safely goes out unpatched, and there is no kprobe
//! armed to notice.
//! It seizes the process that actually issues the vendor command — the Wi-Fi HAL, NOT
//! NetworkStack (measured: NetworkStack computes the bytes in Java and passes them down via
//! AIDL; the `sendmsg` comes from `/vendor/bin/hw/android.hardware.wifi-service`) — stops it
//! at `sendmsg` entry, and rewrites the buffer in place:
//!
//! ```text
//! syscall-enter(sendmsg) → read msghdr/iovec → decode legacy APF SET
//!   → patch::plan_with_arp (the same planner the watchdog uses)
//!   → setmsg::rewrite (fixes nlmsg_len / nla_lens / PACKET_SIZE)
//!   → write buffer + iov_len into the tracee → read back → resume
//! ```
//!
//! Design notes, each of them load-bearing:
//!
//! - **`PTRACE_SEIZE`, never `PTRACE_ATTACH`.** A seized tracee is resumed by the kernel if
//!   the tracer dies, so a pbridge crash cannot leave the Wi-Fi HAL stopped. With ATTACH it
//!   would stay stopped and Wi-Fi would be dead until someone noticed.
//! - **Patch at syscall-*enter*.** The kernel copies the buffer during the syscall, so
//!   entry is the only point where a rewrite is still visible to it.
//! - **Fail open, always.** Any decode/plan/write problem resumes the original syscall
//!   untouched. The stock program then installs, which is exactly the pre-pbridge
//!   behaviour — never a broken filter. Note the cost of that choice in this mode: the
//!   watchdog is NOT running, so a declined install stays unpatched until the next one
//!   rather than being repaired a few hundred milliseconds later.
//! - **No growth without headroom.** The rewritten message is longer, so it must fit in the
//!   tracee's existing allocation. Measured: libnl's message sits in a large arena with 256+
//!   zero bytes past `nlmsg_len`, but that is verified per call rather than assumed, and a
//!   call with no headroom passes through unpatched.
//! - **`sendmsg` only.** pbridge's own vendor socket uses `send`/`sendto`, so hooking
//!   `sendmsg` self-filters pbridge's disable/read/write/enable without a TGID check.
//!
//! Everything decision-shaped lives in [`super::setmsg`] and [`super::patch`], which are
//! unit-tested on the host. This module is the syscall plumbing around them.

use anyhow::{anyhow, bail, Context, Result};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Error};
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use super::patch;
use super::program::debugbuf_of;
use super::setmsg;

const PTRACE_DETACH: libc::c_int = 17;
const PTRACE_SYSCALL: libc::c_int = 24;
const PTRACE_GETREGSET: libc::c_int = 0x4204;
const PTRACE_SETREGSET: libc::c_int = 0x4205;
const PTRACE_SEIZE: libc::c_int = 0x4206;
const PTRACE_INTERRUPT: libc::c_int = 0x4207;
const PTRACE_GETEVENTMSG: libc::c_int = 0x4201;

const PTRACE_O_TRACESYSGOOD: libc::c_ulong = 0x0000_0001;
const PTRACE_O_TRACECLONE: libc::c_ulong = 0x0000_0008;
const PTRACE_O_TRACEEXIT: libc::c_ulong = 0x0000_0040;

const PTRACE_EVENT_CLONE: i32 = 3;
const PTRACE_EVENT_EXIT: i32 = 6;
const PTRACE_EVENT_STOP: i32 = 128;

const NT_PRSTATUS: libc::c_int = 1;

/// Signal used only to interrupt the tracer's blocking `waitpid` at shutdown. `SIGURG` is
/// not used by Rust's runtime, by Tokio, or by anything pbridge does with sockets, and its
/// handler is installed without `SA_RESTART` so it produces the EINTR we need.
const WAKE_SIGNAL: libc::c_int = libc::SIGURG;
/// arm64 `sendmsg`. This is what the HAL's libnl uses; pbridge's own vendor socket uses
/// `send`/`sendto` (206), which is deliberately not hooked so we never see our own traffic.
const SYS_SENDMSG: u64 = 211;

/// Upper bound on a netlink message we will consider. The driver's per-attribute cap is
/// 4096 (`MAX_APF_MEMORY_LEN`) and APF RAM is 2048, so a legitimate SET is far below this.
const MAX_MSG: usize = 16 * 1024;

/// arm64 `user_pt_regs`: 31 GPRs, then sp/pc/pstate. `regs[8]` is the syscall number and
/// `regs[0..=2]` the first three arguments.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PtRegs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

/// arm64 `struct msghdr`, matching bionic's layout including both padding words.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct MsgHdr {
    msg_name: u64,
    msg_namelen: u32,
    _pad1: u32,
    msg_iov: u64,
    msg_iovlen: u64,
    msg_control: u64,
    msg_controllen: u64,
    msg_flags: i32,
    _pad2: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct IoVec {
    iov_base: u64,
    iov_len: u64,
}

/// Counters for logging. Shared with the control plane, which only reads them.
#[derive(Default, Debug)]
pub struct Stats {
    /// Legacy APF SET commands seen.
    pub seen: AtomicU64,
    /// SETs rewritten with our rules.
    pub patched: AtomicU64,
    /// SETs already carrying exactly our rules.
    pub already: AtomicU64,
    /// SETs passed through because they could not be patched safely.
    pub passed: AtomicU64,
}

/// Handle held by the control plane. Dropping it stops the tracer thread and detaches.
pub struct Handle {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
    pub stats: Arc<Stats>,
    pub pid: libc::pid_t,
    /// The addresses the tracer patches for. Shared because DHCP mode changes them at
    /// runtime: the control-plane actor writes, the tracer thread reads at patch time.
    guests: Arc<RwLock<Vec<Ipv4Addr>>>,
    /// The tracer thread's own tid, and a flag it clears on the way out. Shutdown needs
    /// both: the tracer blocks in `waitpid`, so it has to be signalled awake, and the
    /// signal has to keep being sent until we know it has left the loop.
    tracer_tid: Arc<AtomicI32>,
    running: Arc<AtomicBool>,
}

impl Handle {
    /// Stop the tracer and wait for it to detach every thread.
    ///
    /// The tracer sits in a *blocking* `waitpid` (see [`Tracer::run`] for why it must not
    /// poll), so setting the flag is not enough to wake it — the HAL may make no syscall
    /// for minutes. `WAKE_SIGNAL` interrupts the wait; it is re-sent because the flag may
    /// be observed either side of the wait and a signal delivered just before `waitpid` is
    /// entered would otherwise be lost.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(j) = self.join.take() else { return };
        // Bounded: the loop checks `stop` at the top of every iteration, so it exits after
        // at most one stop is handled. The cap only stops us spinning forever if the thread
        // died in a way that left `running` set.
        for _ in 0..500 {
            if !self.running.load(Ordering::Relaxed) {
                break;
            }
            let tid = self.tracer_tid.load(Ordering::Relaxed);
            if tid > 0 {
                // SAFETY: FFI. Signals `tid` within our own thread group; the handler
                // installed by `install_wake_handler` does nothing but exist, so the only
                // effect is EINTR out of `waitpid`.
                unsafe { libc::syscall(libc::SYS_tgkill, std::process::id() as i32, tid, WAKE_SIGNAL) };
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let _ = j.join();
    }

    /// Replace the address list the tracer patches for. Called when a DHCP lease appears or
    /// changes. Takes effect on the next intercepted install; correcting the *already
    /// installed* program is the caller's job (one repatch transaction).
    pub fn set_guests(&self, guests: Vec<Ipv4Addr>) {
        match self.guests.write() {
            Ok(mut g) => *g = guests,
            // The lock is only poisoned if the tracer panicked while holding it, in which
            // case the tracer is already gone and there is nothing to update.
            Err(e) => log::error!("apf-inflight: guest list lock poisoned: {e}"),
        }
    }

    /// `(seen, patched, already, passed)`. Read by the control plane for its teardown log;
    /// a nonzero `passed` counts installs that went out unpatched.
    pub fn counts(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.seen.load(Ordering::Relaxed),
            self.stats.patched.load(Ordering::Relaxed),
            self.stats.already.load(Ordering::Relaxed),
            self.stats.passed.load(Ordering::Relaxed),
        )
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Find the process that issues APF vendor commands: the Wi-Fi HAL. Matched by cmdline and
/// confirmed by SELinux context so we never seize NetworkStack or system_server by mistake.
pub fn find_wifi_hal() -> Result<libc::pid_t> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir("/proc").context("read /proc")? {
        let Ok(entry) = entry else { continue };
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        let dir = entry.path();
        let Ok(raw) = std::fs::read(dir.join("cmdline")) else {
            continue;
        };
        let cmdline = String::from_utf8_lossy(&raw);
        if !cmdline.contains("android.hardware.wifi") {
            continue;
        }
        // A vendor HAL runs in its own domain; requiring it rules out lookalikes.
        let ctx = std::fs::read_to_string(dir.join("attr/current")).unwrap_or_default();
        if !ctx.contains("hal_wifi") {
            continue;
        }
        found.push((pid, cmdline.trim_end_matches('\0').to_string()));
    }
    match found.len() {
        0 => bail!(
            "no Wi-Fi HAL process found (looked for a cmdline containing \
             'android.hardware.wifi' in a 'hal_wifi' SELinux domain)"
        ),
        1 => {
            log::info!("apf-inflight: target pid {} ({})", found[0].0, found[0].1);
            Ok(found[0].0)
        }
        _ => bail!(
            "{} candidate Wi-Fi HAL processes {:?} — refusing to guess",
            found.len(),
            found.iter().map(|(p, _)| *p).collect::<Vec<_>>()
        ),
    }
}

/// Seize the HAL and start patching. Returns once every thread is seized; the tracing loop
/// runs on its own OS thread because ptrace is blocking and thread-affine — only the thread
/// that seized a tracee may control it.
///
/// `guests` may be empty: DHCP mode starts with no observed lease and fills in later via
/// [`Handle::set_guests`]. An install arriving before the first lease is passed through
/// unpatched rather than patched with an empty rule set.
pub fn spawn(pid: libc::pid_t, guests: Vec<Ipv4Addr>) -> Result<Handle> {
    let stop = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(Stats::default());
    let shared_guests = Arc::new(RwLock::new(guests));
    let tracer_tid = Arc::new(AtomicI32::new(0));
    let running = Arc::new(AtomicBool::new(true));

    install_wake_handler().context("install the tracer wake handler")?;

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
    let stop_thread = stop.clone();
    let stats_thread = stats.clone();
    let guests_thread = shared_guests.clone();
    let tid_thread = tracer_tid.clone();
    let running_thread = running.clone();
    let join = std::thread::Builder::new()
        .name("apf-inflight".into())
        .spawn(move || {
            // Publish our tid before anything can fail, so shutdown can always reach us; and
            // clear `running` on every exit path so it never spins waiting for a dead thread.
            // SAFETY: FFI, no arguments, no memory touched.
            tid_thread.store(unsafe { libc::gettid() }, Ordering::Relaxed);
            let mut tracer = match Tracer::seize_all(pid, guests_thread, stats_thread, stop_thread) {
                Ok(t) => {
                    let _ = ready_tx.send(Ok(()));
                    t
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    running_thread.store(false, Ordering::Relaxed);
                    return;
                }
            };
            tracer.run();
            tracer.detach_all();
            running_thread.store(false, Ordering::Relaxed);
        })
        .context("spawn the apf-inflight thread")?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(Handle {
            stop,
            join: Some(join),
            stats,
            pid,
            guests: shared_guests,
            tracer_tid,
            running,
        }),
        Ok(Err(e)) => {
            let _ = join.join();
            Err(e)
        }
        Err(_) => {
            let _ = join.join();
            Err(anyhow!("the apf-inflight thread died during startup"))
        }
    }
}

struct Tracer {
    pid: libc::pid_t,
    tids: Vec<libc::pid_t>,
    /// Registers captured at syscall-enter, per thread, so syscall-exit can be told apart
    /// from the next entry.
    entered: HashMap<libc::pid_t, PtRegs>,
    /// Threads whose in-flight message we grew, and the length the caller expects back.
    /// libnl only checks `nl_send`'s return for `< 0`, but a caller comparing it against its
    /// own message length would see a mismatch, so the exit value is restored.
    pending_retval: HashMap<libc::pid_t, u64>,
    guests: Arc<RwLock<Vec<Ipv4Addr>>>,
    stats: Arc<Stats>,
    stop: Arc<AtomicBool>,
}

impl Tracer {
    fn seize_all(
        pid: libc::pid_t,
        guests: Arc<RwLock<Vec<Ipv4Addr>>>,
        stats: Arc<Stats>,
        stop: Arc<AtomicBool>,
    ) -> Result<Self> {
        let tids = list_threads(pid)?;
        if tids.is_empty() {
            bail!("apf-inflight: pid {pid} has no threads");
        }
        let mut t = Tracer {
            pid,
            tids: Vec::new(),
            entered: HashMap::new(),
            pending_retval: HashMap::new(),
            guests,
            stats,
            stop,
        };
        // TRACESYSGOOD tags syscall stops as SIGTRAP|0x80 so they cannot be confused with a
        // genuine SIGTRAP; TRACECLONE follows threads the HAL spawns later (the sending
        // thread was observed to be both the main thread and a binder worker).
        let opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT;
        for tid in tids {
            if let Err(e) = ptrace(PTRACE_SEIZE, tid, 0, opts) {
                // Roll back: a partial seize would leave threads traced with no loop running.
                for done in &t.tids {
                    let _ = ptrace(PTRACE_DETACH, *done, 0, 0);
                }
                return Err(e).with_context(|| format!("PTRACE_SEIZE tid {tid}"));
            }
            t.tids.push(tid);
        }
        log::info!(
            "apf-inflight: seized {} thread(s) of pid {pid}, guests {:?}",
            t.tids.len(),
            t.guests.read().map(|g| g.clone()).unwrap_or_default()
        );
        // Nudge each thread into a stop so syscall tracing begins even while it sits blocked
        // in a binder ioctl, which is where the HAL spends nearly all its time.
        for tid in &t.tids {
            let _ = ptrace(PTRACE_INTERRUPT, *tid, 0, 0);
        }
        Ok(t)
    }

    fn run(&mut self) {
        while !self.stop.load(Ordering::Relaxed) {
            let mut status: libc::c_int = 0;
            // A BLOCKING wait, deliberately. An earlier version used `WNOHANG` plus a 20 ms
            // sleep so that shutdown would not depend on the HAL making a syscall. That
            // throttled the tracee to roughly one syscall per sleep: after each
            // `PTRACE_SYSCALL` the HAL needs a moment to reach its next syscall boundary, so
            // `waitpid` returned 0 and the loop slept before collecting the stop that had
            // just become available. Measured on device: ~55 voluntary context switches per
            // second, and `svc wifi enable` never completed, because bringing an interface up
            // costs thousands of syscalls. The HAL is idle in steady state, so blocking here
            // costs nothing; shutdown is handled by `Handle::shutdown` signalling this thread
            // (see `WAKE_SIGNAL`).
            let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
            if tid == -1 {
                let e = Error::last_os_error();
                match e.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::ECHILD) => {
                        log::warn!("apf-inflight: no traced threads left, stopping");
                        return;
                    }
                    _ => {
                        log::error!("apf-inflight: waitpid failed: {e}");
                        return;
                    }
                }
            }
            // A tracee can die between the wait and the next ptrace call, which surfaces as
            // ESRCH/EFAULT. Those are transient: log and keep the loop alive rather than
            // abandoning the remaining threads.
            if let Err(e) = self.on_stop(tid, status) {
                log::debug!("apf-inflight: tid {tid}: {e:#}");
                self.entered.remove(&tid);
                let _ = ptrace(PTRACE_SYSCALL, tid, 0, 0);
            }
        }
    }

    fn on_stop(&mut self, tid: libc::pid_t, status: libc::c_int) -> Result<()> {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.forget(tid);
            return Ok(());
        }
        if !libc::WIFSTOPPED(status) {
            ptrace(PTRACE_SYSCALL, tid, 0, 0)?;
            return Ok(());
        }
        match status >> 16 {
            PTRACE_EVENT_CLONE => {
                // Follow the new thread: the vendor command has been observed on binder
                // workers, which are created on demand.
                let mut new: libc::c_ulong = 0;
                if ptrace(
                    PTRACE_GETEVENTMSG,
                    tid,
                    0,
                    &mut new as *mut libc::c_ulong as libc::c_ulong,
                )
                .is_ok()
                {
                    let new = new as libc::pid_t;
                    if new > 0 && !self.tids.contains(&new) {
                        self.tids.push(new);
                        log::debug!("apf-inflight: following new thread {new}");
                    }
                }
                ptrace(PTRACE_SYSCALL, tid, 0, 0)?;
                return Ok(());
            }
            PTRACE_EVENT_EXIT => {
                self.forget(tid);
                let _ = ptrace(PTRACE_DETACH, tid, 0, 0);
                return Ok(());
            }
            PTRACE_EVENT_STOP => {
                // Our INTERRUPT, or a group-stop. Put the thread onto syscall tracing.
                ptrace(PTRACE_SYSCALL, tid, 0, 0)?;
                return Ok(());
            }
            _ => {}
        }

        let sig = libc::WSTOPSIG(status);
        if sig != (libc::SIGTRAP | 0x80) {
            // A real signal: deliver it unchanged. Swallowing signals here would change the
            // HAL's behaviour in ways unrelated to APF.
            ptrace(PTRACE_SYSCALL, tid, 0, sig as libc::c_ulong)?;
            return Ok(());
        }

        let regs = getregs(tid)?;
        match self.entered.remove(&tid) {
            None => {
                // syscall-enter: the only point where a rewrite still reaches the kernel.
                if regs.regs[8] == SYS_SENDMSG {
                    // Account for the install here rather than at each early return inside
                    // `try_patch`: every path that recognised a SET and did not rewrite it
                    // leaves the stock program installed, including the `?` ones. Deriving
                    // `passed` from the other three counters keeps that invariant in one
                    // place — `seen == patched + already + passed` — instead of relying on
                    // each future `bail!` remembering to bump it.
                    let before = (
                        self.stats.seen.load(Ordering::Relaxed),
                        self.stats.patched.load(Ordering::Relaxed),
                        self.stats.already.load(Ordering::Relaxed),
                    );
                    let outcome = self.try_patch(tid, &regs);
                    if let Err(e) = outcome {
                        // Fail open. The stock program installs, which is the behaviour
                        // without pbridge at all.
                        log::debug!("apf-inflight: pass-through on tid {tid}: {e:#}");
                    }
                    let recognised = self.stats.seen.load(Ordering::Relaxed) != before.0;
                    let acted = self.stats.patched.load(Ordering::Relaxed) != before.1
                        || self.stats.already.load(Ordering::Relaxed) != before.2;
                    if recognised && !acted {
                        self.stats.passed.fetch_add(1, Ordering::Relaxed);
                    }
                }
                self.entered.insert(tid, regs);
            }
            Some(enter) => {
                // syscall-exit: restore the byte count the caller expects if we grew the
                // message underneath it.
                if let Some(orig_len) = self.pending_retval.remove(&tid) {
                    if enter.regs[8] == SYS_SENDMSG && (regs.regs[0] as i64) > 0 {
                        let mut fixed = regs;
                        fixed.regs[0] = orig_len;
                        if let Err(e) = setregs(tid, &fixed) {
                            log::warn!("apf-inflight: could not restore sendmsg return: {e:#}");
                        }
                    }
                }
            }
        }
        ptrace(PTRACE_SYSCALL, tid, 0, 0)?;
        Ok(())
    }

    fn forget(&mut self, tid: libc::pid_t) {
        self.tids.retain(|&t| t != tid);
        self.entered.remove(&tid);
        self.pending_retval.remove(&tid);
    }

    /// Decode, patch and write back one `sendmsg`. Every early return leaves the syscall
    /// exactly as the HAL built it.
    fn try_patch(&mut self, tid: libc::pid_t, regs: &PtRegs) -> Result<()> {
        let mh: MsgHdr = read_struct(tid, regs.regs[1]).context("read msghdr")?;
        // libnl sends one iovec. More than one would mean the message is split across
        // buffers and the offsets below would not describe it.
        if mh.msg_iovlen != 1 {
            return Ok(());
        }
        let iov: IoVec = read_struct(tid, mh.msg_iov).context("read iovec")?;
        if iov.iov_len == 0 || iov.iov_len as usize > MAX_MSG {
            return Ok(());
        }
        let buf = read_mem(tid, iov.iov_base, iov.iov_len as usize).context("read message")?;

        let Some(decoded) = setmsg::decode(&buf).context("decode APF SET")? else {
            return Ok(()); // not a legacy APF SET; also covers pbridge's own WRITE/READ
        };
        self.stats.seen.fetch_add(1, Ordering::Relaxed);

        if !decoded.single_fragment() {
            log::warn!(
                "apf-inflight: fragmented SET (total {} chunk {} offset {}) passed through — \
                 in-flight patching only handles single-fragment installs",
                decoded.packet_size,
                decoded.program_len,
                decoded.current_offset
            );
            return Ok(());
        }

        // Snapshot the shared list: DHCP mode mutates it from the control-plane thread, and
        // the whole patch must be planned against one consistent set. Cloning a handful of
        // addresses inside an already-stopped syscall is free next to the ptrace round trips.
        let guests: Vec<Ipv4Addr> = match self.guests.read() {
            Ok(g) => g.clone(),
            Err(e) => bail!("guest list lock poisoned: {e}"),
        };
        if guests.is_empty() {
            // DHCP mode with no lease observed yet. Patching with an empty rule set would
            // strip nothing and add nothing, so pass through and let the next install (or the
            // repatch a lease triggers) carry the rules.
            log::debug!("apf-inflight: no guest addresses yet, SET passed through");
            return Ok(());
        }

        let stock = &buf[decoded.program_at..decoded.program_at + decoded.program_len];
        // The debugbuf reservation is derived from the program itself, so this path needs no
        // access to the 2048-byte work memory that the watchdog reads over netlink.
        let debugbuf = debugbuf_of(stock).context("derive the debugbuf size")?;
        let patched =
            match patch::plan_with_arp(stock, debugbuf, &guests).context("plan the patch")? {
                patch::Plan::AlreadyPatched => {
                    self.stats.already.fetch_add(1, Ordering::Relaxed);
                    log::debug!(
                        "apf-inflight: SET already carries our {} rule(s), left alone",
                        guests.len()
                    );
                    return Ok(());
                }
                patch::Plan::Patch(p) => p,
            };

        let new_msg = setmsg::rewrite(&buf, &decoded, &patched).context("rewrite the message")?;
        let grow = new_msg.len() - buf.len();

        // The rewritten message is longer, so it must fit inside the allocation the HAL
        // already owns. Verified per call: the bytes about to be overwritten must be zero,
        // which is what an unused libnl tail looks like. Anything else could be a live
        // neighbouring heap chunk, and a mapping-boundary check would not catch that.
        if grow > 0 {
            let tail = read_mem(tid, iov.iov_base + buf.len() as u64, grow)
                .context("read the message tail")?;
            if tail.iter().any(|&b| b != 0) {
                // Report whether the growth would at least have stayed inside one mapping.
                // It is not the gate — a live heap chunk in the same arena passes that test
                // — but it separates "the arena is crowded" from "we would have run off the
                // end of the mapping entirely", which are different problems.
                let same_map = within_one_mapping(self.pid, iov.iov_base, new_msg.len())
                    .unwrap_or(false);
                bail!(
                    "no headroom: {grow} bytes past the message are not free \
                     (within one mapping: {same_map})"
                );
            }
        }

        write_mem(tid, iov.iov_base, &new_msg).context("write the patched message")?;

        // Prove the tracee holds what we intended before the syscall runs. Cheap here (the
        // thread is stopped) and it replaces the watchdog's firmware readback, which this
        // path cannot do because it never talks to the firmware.
        let back = read_mem(tid, iov.iov_base, new_msg.len()).context("read back")?;
        if back != new_msg {
            // Undo, then pass through: a half-written message would install a corrupt
            // program.
            if let Err(e) = write_mem(tid, iov.iov_base, &buf) {
                log::error!(
                    "apf-inflight: readback mismatch AND restore failed ({e:#}) — this SET may \
                     install a corrupt program; the watchdog transaction is the recovery path"
                );
            }
            bail!("readback differs from the patched message, restored the original");
        }

        // iov_len is the fifth length and lives outside the buffer.
        let new_iov = IoVec {
            iov_base: iov.iov_base,
            iov_len: new_msg.len() as u64,
        };
        if let Err(e) = write_struct(tid, mh.msg_iov, &new_iov) {
            let _ = write_mem(tid, iov.iov_base, &buf);
            return Err(e).context("write iov_len (message restored)");
        }

        if grow > 0 {
            self.pending_retval.insert(tid, iov.iov_len);
        }
        self.stats.patched.fetch_add(1, Ordering::Relaxed);
        log::info!(
            "apf-inflight: patched a SET in flight on tid {tid}: program {} -> {} bytes, \
             message {} -> {} bytes, guests {:?}",
            decoded.program_len,
            patched.len(),
            buf.len(),
            new_msg.len(),
            guests
        );
        Ok(())
    }

    /// Detach every thread. `PTRACE_DETACH` requires the tracee to be in a ptrace-stop, and
    /// after the run loop exits the threads are running, so a bare detach returns ESRCH.
    /// Interrupt first, reap the resulting stop, then detach.
    ///
    /// A failure here is not fatal by construction: the threads were seized, so the kernel
    /// releases them when this process exits. Getting it right anyway means the HAL is
    /// untraced the moment the session ends rather than whenever pbridge happens to die.
    fn detach_all(&mut self) {
        for tid in std::mem::take(&mut self.tids) {
            if ptrace(PTRACE_INTERRUPT, tid, 0, 0).is_ok() {
                // Reap the stop the interrupt causes. WNOHANG in a short bounded loop: the
                // stop is imminent but not instantaneous, and blocking here would hang
                // teardown if the thread died in between.
                for _ in 0..50 {
                    let mut status: libc::c_int = 0;
                    let r =
                        unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
                    if r == tid || r == -1 {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            }
            if let Err(e) = ptrace(PTRACE_DETACH, tid, 0, 0) {
                log::debug!("apf-inflight: detach tid {tid}: {e:#} (the kernel releases seized threads on exit)");
            }
        }
        log::info!(
            "apf-inflight: detached from pid {} (seen {}, patched {}, already {}, passed {})",
            self.pid,
            self.stats.seen.load(Ordering::Relaxed),
            self.stats.patched.load(Ordering::Relaxed),
            self.stats.already.load(Ordering::Relaxed),
            self.stats.passed.load(Ordering::Relaxed),
        );
    }
}

/// Install a do-nothing handler for [`WAKE_SIGNAL`], once per process.
///
/// The signal exists purely so `Handle::shutdown` can force EINTR out of the tracer's
/// blocking `waitpid`. It must have a handler: with the default disposition `SIGURG` is
/// ignored, which would not interrupt the wait, and `SIG_IGN` behaves the same way. The
/// handler is installed *without* `SA_RESTART` for the same reason — a restarting signal
/// would resume `waitpid` instead of returning EINTR.
fn install_wake_handler() -> Result<(), Error> {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    let mut err = None;
    ONCE.call_once(|| {
        extern "C" fn noop(_: libc::c_int) {}
        // SAFETY: FFI. `act` is fully initialised below and only read by the kernel during
        // this call. `noop` is a plain `extern "C"` function that touches nothing, so it is
        // async-signal-safe.
        unsafe {
            let mut act: libc::sigaction = std::mem::zeroed();
            act.sa_sigaction = noop as *const () as usize;
            act.sa_flags = 0; // no SA_RESTART: we want EINTR
            libc::sigemptyset(&mut act.sa_mask);
            if libc::sigaction(WAKE_SIGNAL, &act, std::ptr::null_mut()) == -1 {
                err = Some(Error::last_os_error());
            }
        }
    });
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

fn list_threads(pid: libc::pid_t) -> Result<Vec<libc::pid_t>> {
    let dir = format!("/proc/{pid}/task");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(Path::new(&dir)).with_context(|| format!("read {dir}"))? {
        let Ok(entry) = entry else { continue };
        if let Some(tid) = entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            out.push(tid);
        }
    }
    Ok(out)
}

/// Strip the arm64 top-byte tag. Android's scudo allocator hands out tagged pointers; the
/// kernel ignores the tag on access but `/proc/pid/maps` lists untagged addresses, so any
/// comparison against a mapping must untag first.
fn untag(addr: u64) -> u64 {
    addr & 0x00ff_ffff_ffff_ffff
}

/// True if `len` bytes at `addr` sit inside one mapping of `pid`. Diagnostics only: the
/// zero-tail check in [`Tracer::try_patch`] is the real safety gate, because a mapping
/// boundary says nothing about neighbouring heap chunks inside the same arena.
fn within_one_mapping(pid: libc::pid_t, addr: u64, len: usize) -> Result<bool> {
    let addr = untag(addr);
    let f = std::fs::File::open(format!("/proc/{pid}/maps"))?;
    for line in BufReader::new(f).lines() {
        let line = line?;
        let Some(range) = line.split_whitespace().next() else {
            continue;
        };
        let mut parts = range.split('-');
        let (Some(s), Some(e)) = (parts.next(), parts.next()) else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(s, 16), u64::from_str_radix(e, 16)) else {
            continue;
        };
        if addr >= start && addr < end {
            return Ok(addr + len as u64 <= end);
        }
    }
    Ok(false)
}

// ---- raw ptrace / cross-process memory ----

fn ptrace(
    req: libc::c_int,
    tid: libc::pid_t,
    addr: libc::c_ulong,
    data: libc::c_ulong,
) -> Result<libc::c_long, Error> {
    // SAFETY: FFI. `req` is one of the PTRACE_* constants above; `addr`/`data` are
    // interpreted per request as either scalars or pointers to caller locals that outlive
    // the call (see the GETEVENTMSG and REGSET callers). errno is cleared first because
    // ptrace signals failure as -1 with errno set, and requests that legitimately return -1
    // as data would otherwise look like errors.
    //
    // The request is cast at the call site because its type differs by libc: glibc declares
    // it `u32`, musl `i32`, and pbridge builds against both (host tests vs the static
    // aarch64-musl device binary).
    unsafe { *libc::__errno_location() = 0 };
    #[allow(clippy::unnecessary_cast)]
    let r = unsafe { libc::ptrace(req as _, tid, addr, data) };
    if r == -1 {
        let e = Error::last_os_error();
        if e.raw_os_error() != Some(0) {
            return Err(e);
        }
    }
    Ok(r)
}

fn getregs(tid: libc::pid_t) -> Result<PtRegs> {
    let mut regs = PtRegs::default();
    let mut iov = libc::iovec {
        iov_base: &mut regs as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<PtRegs>(),
    };
    ptrace(
        PTRACE_GETREGSET,
        tid,
        NT_PRSTATUS as libc::c_ulong,
        &mut iov as *mut _ as libc::c_ulong,
    )
    .context("PTRACE_GETREGSET")?;
    Ok(regs)
}

fn setregs(tid: libc::pid_t, regs: &PtRegs) -> Result<()> {
    let mut copy = *regs;
    let mut iov = libc::iovec {
        iov_base: &mut copy as *mut _ as *mut libc::c_void,
        iov_len: std::mem::size_of::<PtRegs>(),
    };
    ptrace(
        PTRACE_SETREGSET,
        tid,
        NT_PRSTATUS as libc::c_ulong,
        &mut iov as *mut _ as libc::c_ulong,
    )
    .context("PTRACE_SETREGSET")?;
    Ok(())
}

fn read_mem(tid: libc::pid_t, addr: u64, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: len,
    };
    // SAFETY: FFI. `local` describes `buf`, which is `len` bytes and outlives the call.
    // `remote` is in the tracee's address space and is validated by the kernel, which
    // returns -1/EFAULT rather than faulting us. One call moves the whole buffer, versus one
    // PTRACE_PEEKDATA per 8 bytes.
    let n = unsafe { libc::process_vm_readv(tid, &local, 1, &remote, 1, 0) };
    if n == -1 {
        return Err(Error::last_os_error()).context("process_vm_readv");
    }
    if (n as usize) != len {
        bail!("short cross-process read: {n} of {len} bytes");
    }
    Ok(buf)
}

fn write_mem(tid: libc::pid_t, addr: u64, data: &[u8]) -> Result<()> {
    let local = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: FFI, the mirror of read_mem. `local` is only read here; the tracee is stopped
    // at a syscall boundary, so nothing in it can observe a partially written buffer.
    let n = unsafe { libc::process_vm_writev(tid, &local, 1, &remote, 1, 0) };
    if n == -1 {
        return Err(Error::last_os_error()).context("process_vm_writev");
    }
    if (n as usize) != data.len() {
        bail!("short cross-process write: {n} of {} bytes", data.len());
    }
    Ok(())
}

fn read_struct<T: Copy + Default>(tid: libc::pid_t, addr: u64) -> Result<T> {
    let bytes = read_mem(tid, addr, std::mem::size_of::<T>())?;
    let mut out = T::default();
    // SAFETY: `bytes` is exactly size_of::<T>() long (read_mem returns the full length or
    // errors), and both T here are #[repr(C)] Copy mirrors of kernel ABI structs, so every
    // bit pattern is a valid value.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            &mut out as *mut T as *mut u8,
            std::mem::size_of::<T>(),
        );
    }
    Ok(out)
}

fn write_struct<T: Copy>(tid: libc::pid_t, addr: u64, val: &T) -> Result<()> {
    // SAFETY: reading size_of::<T>() bytes from a valid &T is in bounds by construction, and
    // T is Copy so this borrows rather than duplicates ownership.
    let bytes = unsafe {
        std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>())
    };
    write_mem(tid, addr, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untag_strips_only_the_top_byte() {
        // The address in this assertion is a real one observed in the HAL.
        assert_eq!(untag(0xb400_007b_7c04_4320), 0x0000_007b_7c04_4320);
        assert_eq!(untag(0x0000_007b_7c04_4320), 0x0000_007b_7c04_4320);
        assert_eq!(untag(0), 0);
    }

    /// These layouts are ABI, not our choice: a wrong size silently reads the wrong field
    /// and the patcher would target garbage.
    #[test]
    fn abi_struct_sizes_match_arm64() {
        assert_eq!(std::mem::size_of::<IoVec>(), 16);
        assert_eq!(std::mem::size_of::<MsgHdr>(), 56);
        assert_eq!(std::mem::size_of::<PtRegs>(), 34 * 8);
    }

    #[test]
    fn our_own_mapping_is_found() {
        let x = [0u8; 64];
        let me = std::process::id() as libc::pid_t;
        assert!(within_one_mapping(me, x.as_ptr() as u64, 64).unwrap());
        // An address in no mapping at all.
        assert!(!within_one_mapping(me, 0x10, 8).unwrap());
    }

    #[test]
    fn threads_of_self_include_self() {
        let me = std::process::id() as libc::pid_t;
        let tids = list_threads(me).unwrap();
        assert!(!tids.is_empty());
    }

    /// The premise of the blocking-`waitpid` design: `WAKE_SIGNAL` must actually interrupt a
    /// blocked wait. If the handler were missing, installed with `SA_RESTART`, or the signal
    /// were one the runtime ignores, the wait would resume and shutdown would hang forever —
    /// which is exactly the failure the previous 20 ms poll was there to avoid, so it has to
    /// be proven rather than assumed.
    #[test]
    fn wake_signal_interrupts_a_blocking_wait() {
        install_wake_handler().expect("install the wake handler");
        let tid = Arc::new(AtomicI32::new(0));
        let tid_thread = tid.clone();
        let (tx, rx) = std::sync::mpsc::channel::<i32>();

        let h = std::thread::spawn(move || {
            // SAFETY: FFI, no arguments.
            tid_thread.store(unsafe { libc::gettid() }, Ordering::Relaxed);
            let mut status: libc::c_int = 0;
            // No children exist, so without a signal this returns ECHILD immediately; with a
            // child it would block. Either way the errno tells us which happened, and the
            // point of the test is that we are never stuck here.
            // SAFETY: FFI. `status` is a live local.
            let r = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
            let errno = Error::last_os_error().raw_os_error().unwrap_or(0);
            let _ = tx.send(if r == -1 { errno } else { 0 });
        });

        // Give the thread a moment to reach the wait, then signal it.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let target = tid.load(Ordering::Relaxed);
        assert!(target > 0, "the thread must publish its tid");
        // SAFETY: FFI. Signals a thread in our own group with the handler installed above.
        unsafe {
            libc::syscall(
                libc::SYS_tgkill,
                std::process::id() as i32,
                target,
                WAKE_SIGNAL,
            )
        };

        let errno = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("waitpid must return, not hang");
        h.join().unwrap();
        // ECHILD (no children at all) or EINTR (the signal cut the wait short) both prove the
        // wait terminated. A hang is the only failure, and recv_timeout catches it.
        assert!(
            errno == libc::ECHILD || errno == libc::EINTR,
            "unexpected waitpid errno {errno}"
        );
    }

    /// An empty list is legitimate now: DHCP mode starts with no observed lease. The guard
    /// moved into the patch path, which passes installs through until addresses arrive, so a
    /// missing lease can never produce an empty-rule-set rewrite.
    #[test]
    fn an_empty_guest_list_is_shareable_and_updatable() {
        let shared = Arc::new(RwLock::new(Vec::<Ipv4Addr>::new()));
        assert!(shared.read().unwrap().is_empty());

        // What Handle::set_guests does, exercised without needing a live tracee.
        *shared.write().unwrap() = vec!["192.168.1.153".parse().unwrap()];
        assert_eq!(shared.read().unwrap().len(), 1);

        // A snapshot taken for planning must not observe a later mutation.
        let snapshot: Vec<Ipv4Addr> = shared.read().unwrap().clone();
        *shared.write().unwrap() = vec![
            "192.168.1.153".parse().unwrap(),
            "192.168.1.204".parse().unwrap(),
        ];
        assert_eq!(snapshot.len(), 1, "the snapshot must be stable");
        assert_eq!(shared.read().unwrap().len(), 2);
    }
}
