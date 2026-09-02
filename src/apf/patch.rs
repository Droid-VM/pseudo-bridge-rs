//! APF program patcher: insert "pass ICMP echo request to these guests" ahead of the
//! vendor's unconditional `DROPPED_ICMP_ECHO`, and fix every jump the insertion moves.
//!
//! Port of the validated `apf/tools/apf_patch.py` algorithm, with the single-guest
//! insertion generalised to N guests. The rules that matter (all measured, see
//! `apf/README.md` §"打补丁并实测"):
//!
//! - A jump target is always `insn_end + imm`; `target == program_len` encodes PASS and
//!   `program_len + 1` encodes DROP, so both shift with the program and need the same
//!   arithmetic as any other crossing jump.
//! - Inserting `delta` bytes at `P` bumps `imm` by `delta` for every jump with
//!   `end <= P <= target`. `end == P` counts: such an instruction keeps its own bytes but
//!   its target moves (the live program's `jne r0,0x8,<after-drop>` is exactly this case).
//! - `program_len + debugbuf_size` is a constant (APF RAM minus the counter region), so
//!   the debugbuf reservation shrinks by `delta`.

use super::program::{
    parse, Insn, EXCEPTIONBUFFER_EXT, EXT, JEQ, JNE, LDB, LDH, LDW, PASSDROP,
    PROGRAM_PLUS_DEBUGBUF,
};
use anyhow::{bail, Result};
use std::net::Ipv4Addr;

/// `ldw r0,[30]`: opcode byte + 1-byte immediate.
const LDW_BYTES: usize = 2;
/// `jeq r0,<ipv4>,PASS`: opcode byte + 4-byte jump offset + 4-byte compare immediate.
const JEQ_BYTES: usize = 9;
/// Xiaomi vendor counter for the ICMP echo drop (`DROPPED_ICMP_ECHO`).
const ICMP_DROP_COUNTER: u32 = 21;
const OFF_V4_PROTO: u32 = 23;
const OFF_V4_ARP_TPA: u32 = 38;
const OFF_V4_DST: u32 = 30;
const OFF_ICMP_TYPE: u32 = 34;
/// ARP opcode: 14-byte ethernet header + 6 bytes into the ARP header.
const OFF_ARP_OPCODE: u32 = 20;
const ARP_OP_REQUEST: u32 = 1;
const PROTO_ICMP: u32 = 1;
const ICMP_ECHO_REQUEST: u32 = 8;

#[derive(Debug)]
#[allow(dead_code)] // ICMP-only compatibility plan uses this; watchdog's ARP-aware plan rewrites its own patch.
pub enum Plan {
    /// The live program already carries exactly these rules; writing would be a no-op.
    AlreadyPatched,
    /// The patched program to install.
    Patch(Vec<u8>),
}

/// Original ICMP-only patch plan, retained for compatibility fixtures and callers that do
/// not opt into ARP workarounds.
#[cfg_attr(not(test), allow(dead_code))]
pub fn plan(prog: &[u8], debugbuf_size: usize, guests: &[Ipv4Addr]) -> Result<Plan> {
    let insns = parse(prog)?;
    if let Some(found) = find_our_rules(prog, &insns)? {
        if found == guests {
            return Ok(Plan::AlreadyPatched);
        }
        let stock = remove_our_rules(prog, &insns, &found)?;
        let stock_insns = parse(&stock)?;
        let stock_dbg = debugbuf_size_of(&stock, &stock_insns)?;
        let site = find_icmp_drop_site(&stock, &stock_insns)?;
        return Ok(Plan::Patch(apply(
            &stock,
            &stock_insns,
            site,
            stock_dbg,
            guests,
        )?));
    }
    let site = find_icmp_drop_site(prog, &insns)?;
    Ok(Plan::Patch(apply(
        prog,
        &insns,
        site,
        debugbuf_size,
        guests,
    )?))
}

/// ICMP plus destination-specific ARP patch. Used by pbridge's normal APF watchdog so
/// guest v4 `/32` addresses no longer need to be assigned to wlan0.
pub fn plan_with_arp(prog: &[u8], debugbuf_size: usize, guests: &[Ipv4Addr]) -> Result<Plan> {
    let insns = parse(prog)?;

    // Recover the stock program by stripping whatever we previously inserted. Both shapes have
    // to be handled independently: on a steady-state program only the ARP rules exist, and an
    // earlier version looked for the ICMP ones alone — so it never recognised its own work,
    // and then failed outright because the site locator does not match an already-patched
    // branch (`ldw / vendor jeq / our jeq` no longer ends in the `drop` it looks for).
    let (stock, stock_insns, stock_dbg) = if let Some(found) = find_our_rules(prog, &insns)? {
        // `remove_our_rules` also strips a co-resident ARP insertion.
        let stock = remove_our_rules(prog, &insns, &found)?;
        let parsed = parse(&stock)?;
        let dbg = debugbuf_size_of(&stock, &parsed)?;
        (stock, parsed, dbg)
    } else if let Some(found) = find_our_arp_rules(prog, &insns)? {
        let stock = remove_arp_rules(prog, &insns, &found)?;
        let parsed = parse(&stock)?;
        let dbg = debugbuf_size_of(&stock, &parsed)?;
        (stock, parsed, dbg)
    } else {
        (prog.to_vec(), insns, debugbuf_size)
    };

    let planned = plan_stock(&stock, &stock_insns, stock_dbg, guests)?;
    // "Already patched" means: re-deriving from the recovered stock reproduces exactly what is
    // running. Comparing the finished bytes rather than reasoning about which sites ought to
    // carry rules keeps this correct whichever subset of sites the program happens to have.
    match planned {
        Plan::Patch(p) if p == prog => Ok(Plan::AlreadyPatched),
        other => Ok(other),
    }
}

fn plan_stock(
    prog: &[u8],
    insns: &[Insn],
    debugbuf_size: usize,
    guests: &[Ipv4Addr],
) -> Result<Plan> {
    // The two sites are independent, and which of them exists is build- and
    // state-dependent. Measured on warsaw:
    //
    // - The ARP request drop is present in every steady-state program and is what actually
    //   blocks a peer from resolving the guest (a capture with `--arp-keepalive 0` shows the
    //   peer's ARP never reaching wlan0 at all).
    // - The ICMP echo drop that `find_icmp_drop_site` wants is present only in the tiny
    //   366/377-byte programs installed at vdev bring-up. In steady state the echo branch is
    //   gated on the destination being the phone's own IPv4 and answered in firmware, so the
    //   shape is genuinely absent.
    //
    // So neither may be treated as mandatory. An earlier version tolerated a missing ARP
    // site but `?`-propagated a missing ICMP one, which made every steady-state repatch fail
    // even though the ARP rules — the ones that matter — were available to install.
    let arp_site = find_arp_request_drop_site(prog, insns);
    let icmp_site = find_icmp_drop_site(prog, insns);
    let (arp_err, icmp_err) = (arp_site.as_ref().err(), icmp_site.as_ref().err());
    if let (Some(a), Some(i)) = (arp_err, icmp_err) {
        bail!("no patchable site in this APF program — ARP: {a}; ICMP: {i}");
    }
    if let Some(e) = arp_err {
        log::debug!("apf: no ARP request drop site to patch ({e}); patching ICMP only");
    }
    if let Some(e) = icmp_err {
        log::debug!("apf: no ICMP echo drop site to patch ({e}); patching ARP only");
    }

    // Both insertion blobs address PASS in the *final* program, so the total delta has to be
    // known before either splice. Splice the higher offset first: then the lower splice's
    // jump fix-up leaves the already-inserted block's jeqs alone (their `end` is past the
    // lower insertion point), while every crossing jump still accumulates both deltas.
    let arp_delta = arp_site.as_ref().map_or(0, |_| JEQ_BYTES * guests.len());
    let icmp_delta = icmp_site
        .as_ref()
        .map_or(0, |_| LDW_BYTES + JEQ_BYTES * guests.len());
    let final_len = prog.len() + arp_delta + icmp_delta;
    if final_len > PROGRAM_PLUS_DEBUGBUF {
        bail!("patched program {final_len} bytes exceeds the APF executable budget");
    }

    // Each block's insertion point is a *stock* offset, but its `jeq` offsets are relative to
    // the FINAL layout, so a block needs to know how far it will have shifted by then: the
    // sum of the deltas of every block inserted at a lower offset.
    let mut steps: Vec<(usize, usize)> = Vec::new(); // (stock offset, own delta)
    if let Ok(site) = &arp_site {
        steps.push((site.insert_at, arp_delta));
    }
    if let Ok(icmp_at) = &icmp_site {
        steps.push((*icmp_at, icmp_delta));
    }
    steps.sort_by_key(|(at, _)| *at);
    let blobs: Vec<(usize, Vec<u8>)> = steps
        .iter()
        .enumerate()
        .map(|(k, (at, _))| {
            let shift: usize = steps[..k].iter().map(|(_, d)| *d).sum();
            let final_at = at + shift;
            let blob = if Some(*at) == arp_site.as_ref().ok().map(|s| s.insert_at) {
                arp_insertion_bytes(final_at, final_len, guests)
            } else {
                insertion_bytes(final_at, final_len, guests)
            };
            (*at, blob)
        })
        .collect();

    let mut cur = prog.to_vec();
    let mut cur_insns = insns.to_vec();
    let mut cur_dbg = debugbuf_size;

    // Splice DESCENDING. Two properties make this work, and both are load-bearing:
    //
    // - A lower splice must not disturb the jump offsets of an already-inserted higher
    //   block. It cannot: those `jeq`s have `end > insert_at`, which fails `splice`'s
    //   `i.end <= insert_at` crossing test.
    // - Between the two splices the program is a length that no `jeq` was written against,
    //   so the first block's targets (which address the *final* PASS) exceed the intermediate
    //   program's `n + 1`. That is tolerated because `program::parse` computes a jump target
    //   as `end + imm` and only rejects *arithmetic overflow* — it does not range-check
    //   against the program length. `splice` skips those jumps for the same reason
    //   (`target <= n + 1` fails). Only the finished program is range-checked, by
    //   `validate_rules` below.
    for (at, ins) in blobs.iter().rev() {
        cur = splice(&cur, &cur_insns, *at, ins, cur_dbg)?;
        cur_insns = parse(&cur)?;
        cur_dbg = debugbuf_size_of(&cur, &cur_insns)?;
    }

    validate_rules(&cur, arp_site.as_ref().ok().is_some(), icmp_err.is_none(), guests)?;
    if let Ok(site) = &arp_site {
        log::debug!(
            "apf: ARP request pass-list inserted at {} (vendor counter {})",
            site.insert_at,
            site.counter
        );
    }
    Ok(Plan::Patch(cur))
}

/// Locate the vendor's "ARP **request** for an address that is not ours → drop" site, and
/// return the offset of its `drop` (our insertion point).
///
/// Found by following the ARP opcode dispatch rather than by matching a vendor counter
/// number. Measured on warsaw: the program is
///
/// ```text
/// 107: ldh  r0, [20]              # ARP opcode
/// 109: jeq  r0, 0x1, 151          # request  -> the site we want
/// 112: jeq  r0, 0x2, 117          # reply    -> a different branch
/// ...
/// 151: ldw  r0, [38]              # ARP TPA
/// 153: jeq  r0, <our ipv4>, 164   # ours -> firmware synthesises the reply
/// 162: drop counter=13            # not ours -> dropped here
/// ```
///
/// Two things this deliberately does not key on:
///
/// - **The counter number.** An earlier version required `counter=26`; this build uses 13,
///   and hardcoding either one is the same mistake. The counter is now only a cross-check
///   in the caller's log.
/// - **`JNE` vs `JEQ`.** The earlier version required `jne`; this build compares with `jeq`
///   and jumps *away* on a match. Neither matters: any packet that reaches the `drop` has
///   already had the TPA loaded into `r0` by the `ldw [38]` above it, so inserting
///   `jeq r0,<guest>,PASS` immediately before the drop is correct for either polarity.
///
/// The **reply** branch is intentionally left alone. Its non-local drop only guards
/// *broadcast* (gratuitous) ARP replies — a unicast reply passes unconditionally further up
/// (`pass counter=61` at 134), which is why a guest's traffic to the gateway already works.
/// Patching it would admit broadcast GARP for the guest and change nothing about
/// reachability.
fn find_arp_request_drop_site(prog: &[u8], insns: &[Insn]) -> Result<ArpSite> {
    // The dispatch: `ldh r0,[20]` immediately followed by a cmp-jump against opcode 1.
    let mut targets = Vec::new();
    for w in insns.windows(2) {
        let (ldh, j) = (&w[0], &w[1]);
        if ldh.opcode == LDH
            && ldh.reg == 0
            && ldh.imm == OFF_ARP_OPCODE
            && (j.opcode == JEQ || j.opcode == JNE)
            && j.reg == 0
            && cmp_imm(prog, j) == Some(ARP_OP_REQUEST)
        {
            // For `jeq op==1` the request path is the jump target; for `jne op!=1` it is
            // the fall-through. Both shapes appear in AOSP-derived generators.
            match j.opcode {
                JEQ => targets.extend(j.target),
                _ => targets.push(j.end),
            }
        }
    }
    let at = match targets.as_slice() {
        [at] => *at,
        [] => bail!("no ARP opcode dispatch (ldh[20] + cmp against op=1) in this program"),
        _ => bail!(
            "{} ARP request dispatch branches; refusing to guess which one to patch",
            targets.len()
        ),
    };

    // Walk the request branch: `ldw r0,[38]` / cmp-jump / `drop`.
    let k = insns
        .iter()
        .position(|i| i.start == at)
        .ok_or_else(|| anyhow::anyhow!("ARP request branch target {at} is not an instruction"))?;
    let w = insns
        .get(k..k + 3)
        .ok_or_else(|| anyhow::anyhow!("ARP request branch at {at} is truncated"))?;
    let (ldw, cmp, drop) = (&w[0], &w[1], &w[2]);
    if !(ldw.opcode == LDW && ldw.reg == 0 && ldw.imm == OFF_V4_ARP_TPA) {
        bail!("ARP request branch at {at} does not start with ldw r0,[38]");
    }
    if !((cmp.opcode == JEQ || cmp.opcode == JNE) && cmp.reg == 0 && cmp.imm_len == 4) {
        bail!("ARP request branch at {at} has no 4-byte TPA comparison");
    }
    if !(drop.opcode == PASSDROP && drop.reg == 1) {
        bail!("ARP request branch at {at} does not end in a drop");
    }
    Ok(ArpSite {
        insert_at: drop.start,
        counter: drop.imm,
    })
}

/// Where the ARP pass-list goes, plus the vendor counter that guarded it (logged, so a
/// counter change between builds is visible without being fatal).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct ArpSite {
    insert_at: usize,
    counter: u32,
}

fn arp_insertion_bytes(insert_at: usize, final_len: usize, guests: &[Ipv4Addr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(JEQ_BYTES * guests.len());
    for (k, ip) in guests.iter().enumerate() {
        let end = insert_at + JEQ_BYTES * (k + 1);
        let off = (final_len - end) as u32;
        out.push((JEQ << 3) | (3 << 1));
        out.extend_from_slice(&off.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// Locate the vendor sequence `ldb r0,[23] / jne r0,1 / ldb r0,[34] / jne r0,8 / drop 21`
/// and return the offset of its `drop` (the insertion point). Ambiguity is an error.
fn find_icmp_drop_site(prog: &[u8], insns: &[Insn]) -> Result<usize> {
    let mut sites = Vec::new();
    for w in insns.windows(5) {
        let (a, b, c, d, e) = (&w[0], &w[1], &w[2], &w[3], &w[4]);
        let shape = a.opcode == LDB
            && a.imm == OFF_V4_PROTO
            && b.opcode == JNE
            && b.imm_len > 0
            && c.opcode == LDB
            && c.imm == OFF_ICMP_TYPE
            && d.opcode == JNE
            && d.imm_len > 0
            && e.opcode == PASSDROP
            && e.reg == 1
            && e.imm == ICMP_DROP_COUNTER;
        if shape
            && cmp_imm(prog, b) == Some(PROTO_ICMP)
            && cmp_imm(prog, d) == Some(ICMP_ECHO_REQUEST)
        {
            sites.push(e.start);
        }
    }
    match sites.len() {
        1 => Ok(sites[0]),
        0 => bail!(
            "no vendor ICMP-echo drop site in the live APF program (no \
             ldb[23]/jne 1/ldb[34]/jne 8/drop counter={ICMP_DROP_COUNTER} sequence) — nothing to \
             patch, leaving it alone"
        ),
        n => bail!("{n} candidate ICMP-echo drop sites; refusing to guess which one to patch"),
    }
}

/// A cmp-jump's comparison immediate sits right after its jump offset.
fn cmp_imm(prog: &[u8], i: &Insn) -> Option<u32> {
    if i.reg != 0 || i.imm_len == 0 {
        return None;
    }
    let at = i.imm_at + i.imm_len;
    let end = at + i.imm_len;
    let bytes = prog.get(at..end)?;
    Some(bytes.iter().fold(0u32, |acc, b| (acc << 8) | u32::from(*b)))
}

/// Detect our own insertion: `ldw r0,[30]` followed by N `jeq r0,<ip>,PASS` immediately
/// ahead of a `drop counter=21`. Returns the guest list in program order.
fn find_our_rules(prog: &[u8], insns: &[Insn]) -> Result<Option<Vec<Ipv4Addr>>> {
    let pass = prog.len();
    for (k, drop) in insns.iter().enumerate() {
        if drop.opcode != PASSDROP || drop.reg != 1 || drop.imm != ICMP_DROP_COUNTER {
            continue;
        }
        let mut ips = Vec::new();
        let mut j = k;
        while j > 0 {
            let cand = &insns[j - 1];
            if cand.opcode == JEQ && cand.reg == 0 && cand.imm_len == 4 && cand.target == Some(pass)
            {
                match cmp_imm(prog, cand) {
                    Some(v) => ips.push(Ipv4Addr::from(v)),
                    None => break,
                }
                j -= 1;
            } else {
                break;
            }
        }
        if ips.is_empty() || j == 0 {
            continue;
        }
        let ldw = &insns[j - 1];
        if ldw.opcode == LDW && ldw.reg == 0 && ldw.imm == OFF_V4_DST {
            ips.reverse();
            // Cross-check the bytes: our generator is the only thing that produces this
            // exact encoding, so a byte-identical match makes the detection definitive.
            let want = insertion_bytes(ldw.start, prog.len(), &ips);
            if prog.get(ldw.start..drop.start) == Some(&want[..]) {
                return Ok(Some(ips));
            }
        }
    }
    Ok(None)
}

/// Remove a byte-identical pbridge insertion so a DHCP lease update can replace its guest
/// set. This is deliberately narrower than a general "unpatch" facility: it only accepts
/// the sequence `find_our_rules` recognized, and re-walks the recovered stock program.
fn remove_our_rules(prog: &[u8], insns: &[Insn], guests: &[Ipv4Addr]) -> Result<Vec<u8>> {
    let pass = prog.len();
    let mut range = None;
    for (k, drop) in insns.iter().enumerate() {
        if drop.opcode != PASSDROP || drop.reg != 1 || drop.imm != ICMP_DROP_COUNTER {
            continue;
        }
        let mut j = k;
        let mut count = 0;
        while j > 0 {
            let cand = &insns[j - 1];
            if cand.opcode == JEQ && cand.reg == 0 && cand.imm_len == 4 && cand.target == Some(pass)
            {
                count += 1;
                j -= 1;
            } else {
                break;
            }
        }
        if count != guests.len() || j == 0 {
            continue;
        }
        let ldw = &insns[j - 1];
        if ldw.opcode == LDW && ldw.reg == 0 && ldw.imm == OFF_V4_DST {
            let want = insertion_bytes(ldw.start, prog.len(), guests);
            if prog.get(ldw.start..drop.start) == Some(&want[..]) {
                range = Some((ldw.start, drop.start));
                break;
            }
        }
    }
    let Some((start, end)) = range else {
        bail!("cannot locate the byte-identical pbridge APF insertion to replace");
    };
    let delta = end - start;
    let mut out = Vec::with_capacity(prog.len() - delta);
    out.extend_from_slice(&prog[..start]);
    out.extend_from_slice(&prog[end..]);

    // Invert insertion's crossing-jump adjustment. These jump fields are before `start`,
    // so their byte offsets do not move when the insertion disappears.
    for i in insns {
        let Some(target) = i.target else { continue };
        if i.end <= start && target >= end {
            if i.imm < delta as u32 {
                bail!(
                    "pbridge jump at byte {} underflows while removing prior insertion",
                    i.start
                );
            }
            let new = i.imm - delta as u32;
            let at = i.jump_imm_at.expect("jump target has immediate");
            out[at..at + i.jump_imm_len].copy_from_slice(&new.to_be_bytes()[4 - i.jump_imm_len..]);
        }
    }
    let dbg = debugbuf_size_of(prog, insns)?;
    let dbg_insn = insns
        .iter()
        .find(|i| i.opcode == EXT && i.imm == EXCEPTIONBUFFER_EXT)
        .ok_or_else(|| anyhow::anyhow!("missing debugbuf"))?;
    if dbg_insn.end > start || dbg + delta > u16::MAX as usize {
        bail!("invalid debugbuf while removing prior pbridge insertion");
    }
    let at = dbg_insn.end - 2;
    out[at..at + 2].copy_from_slice(&((dbg + delta) as u16).to_be_bytes());
    let parsed = parse(&out)?;
    if parsed.last().is_none_or(|i| i.end != out.len()) {
        bail!("APF after removing ICMP rules does not walk to its own end");
    }
    remove_arp_rules(&out, &parsed, guests).or(Ok(out))
}

/// Strip our ARP insertion so a DHCP lease update can replace the guest set.
///
/// Shares [`find_our_arp_rules`]'s anchoring, and for the same reason it no longer keys on a
/// vendor counter number: this used to require `drop counter=26`, which does not exist on
/// this build, so a lease change could never remove the rules it had itself installed.
fn remove_arp_rules(prog: &[u8], insns: &[Insn], guests: &[Ipv4Addr]) -> Result<Vec<u8>> {
    let pass = prog.len();
    let mut range = None;
    for (k, drop) in insns.iter().enumerate() {
        if drop.opcode != PASSDROP || drop.reg != 1 {
            continue;
        }
        let mut j = k;
        let mut ips = Vec::new();
        while j > 0 {
            let cand = &insns[j - 1];
            if cand.opcode == JEQ && cand.reg == 0 && cand.imm_len == 4 && cand.target == Some(pass)
            {
                let Some(ip) = cmp_imm(prog, cand).map(Ipv4Addr::from) else {
                    break;
                };
                ips.push(ip);
                j -= 1;
            } else {
                break;
            }
        }
        if ips.is_empty() || j == 0 {
            continue;
        }
        // Same non-adjacent anchor as the detector: the vendor's own TPA compare sits between
        // the `ldw r0,[38]` and our run.
        const MAX_GAP: usize = 2;
        if !insns[..j]
            .iter()
            .rev()
            .take(MAX_GAP + 1)
            .any(|i| i.opcode == LDW && i.reg == 0 && i.imm == OFF_V4_ARP_TPA)
        {
            continue;
        }
        ips.reverse();
        if ips == guests {
            range = Some((insns[j].start, drop.start));
            break;
        }
    }
    let Some((start, end)) = range else {
        bail!("cannot locate the byte-identical pbridge ARP insertion to replace");
    };
    let stock = remove_insertion(prog, insns, start, end)?;
    // Guard against mistaking the vendor's own rule for ours. A `jeq r0,<phone ip>,PASS`
    // emitted by the generator is byte-identical to one of our jeqs (same 4-byte encoding),
    // so shape alone cannot tell them apart. What can: after stripping OUR run, the vendor's
    // `ldw [38] / cmp / drop` branch must still be intact. If it is not, we just removed the
    // phone's own ARP compare, and writing that back would make the phone unreachable.
    let stock_insns = parse(&stock)?;
    if let Err(e) = find_arp_request_drop_site(&stock, &stock_insns) {
        bail!(
            "refusing to strip ARP rules: the remaining program has no vendor ARP request \
             site, so the run was probably the firmware's own rule ({e})"
        );
    }
    Ok(stock)
}

fn remove_insertion(prog: &[u8], insns: &[Insn], start: usize, end: usize) -> Result<Vec<u8>> {
    let delta = end - start;
    let mut out = Vec::with_capacity(prog.len() - delta);
    out.extend_from_slice(&prog[..start]);
    out.extend_from_slice(&prog[end..]);
    for i in insns {
        let Some(target) = i.target else { continue };
        if i.end <= start && target >= end {
            if i.imm < delta as u32 {
                bail!(
                    "pbridge jump at byte {} underflows while removing prior insertion",
                    i.start
                );
            }
            let new = i.imm - delta as u32;
            let at = i.jump_imm_at.expect("jump target has immediate");
            out[at..at + i.jump_imm_len].copy_from_slice(&new.to_be_bytes()[4 - i.jump_imm_len..]);
        }
    }
    let dbg = debugbuf_size_of(prog, insns)?;
    let dbg_insn = insns
        .iter()
        .find(|i| i.opcode == EXT && i.imm == EXCEPTIONBUFFER_EXT)
        .ok_or_else(|| anyhow::anyhow!("missing debugbuf"))?;
    if dbg_insn.end > start || dbg + delta > u16::MAX as usize {
        bail!("invalid debugbuf while removing prior pbridge insertion");
    }
    let at = dbg_insn.end - 2;
    out[at..at + 2].copy_from_slice(&((dbg + delta) as u16).to_be_bytes());
    let parsed = parse(&out)?;
    if parsed.last().is_none_or(|i| i.end != out.len()) {
        bail!("recovered APF stock program does not walk to its own end");
    }
    Ok(out)
}

fn debugbuf_size_of(prog: &[u8], insns: &[Insn]) -> Result<usize> {
    let dbg: Vec<&Insn> = insns
        .iter()
        .filter(|i| i.opcode == EXT && i.imm == EXCEPTIONBUFFER_EXT)
        .collect();
    if dbg.len() != 1 {
        bail!(
            "expected exactly one APF debugbuf instruction, found {}",
            dbg.len()
        );
    }
    let at = dbg[0].end - 2;
    Ok(u16::from_be_bytes(prog[at..at + 2].try_into().unwrap()) as usize)
}

/// The bytes we insert at `insert_at` for a program whose final length is `final_len`.
fn insertion_bytes(insert_at: usize, final_len: usize, guests: &[Ipv4Addr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(LDW_BYTES + JEQ_BYTES * guests.len());
    out.push((LDW << 3) | (1 << 1)); // len_field=1 → 1-byte immediate, register r0
    out.push(OFF_V4_DST as u8);
    for (k, ip) in guests.iter().enumerate() {
        // Each jeq's own end depends on how many precede it; PASS is at final_len.
        let end = insert_at + LDW_BYTES + JEQ_BYTES * (k + 1);
        let off = (final_len - end) as u32;
        out.push((JEQ << 3) | (3 << 1)); // len_field=3 → 4-byte immediates, register r0
        out.extend_from_slice(&off.to_be_bytes());
        out.extend_from_slice(&ip.octets());
    }
    out
}

fn apply(
    prog: &[u8],
    insns: &[Insn],
    insert_at: usize,
    debugbuf_size: usize,
    guests: &[Ipv4Addr],
) -> Result<Vec<u8>> {
    let delta = LDW_BYTES + JEQ_BYTES * guests.len();
    let final_len = prog.len() + delta;
    if final_len > PROGRAM_PLUS_DEBUGBUF {
        bail!("patched program {final_len} bytes exceeds the APF executable budget");
    }
    let ins = insertion_bytes(insert_at, final_len, guests);
    debug_assert_eq!(ins.len(), delta);
    let out = splice(prog, insns, insert_at, &ins, debugbuf_size)?;
    validate(&out, insert_at, guests)?;
    Ok(out)
}

/// The generic "insert bytes at an instruction boundary and repair the program" step.
/// Kept separate (and `pub(crate)`) so the archived single-guest patch can be reproduced
/// byte for byte in tests.
pub(crate) fn splice(
    prog: &[u8],
    insns: &[Insn],
    insert_at: usize,
    ins: &[u8],
    debugbuf_size: usize,
) -> Result<Vec<u8>> {
    let n = prog.len();
    let delta = ins.len();
    if !insns.iter().any(|i| i.start == insert_at) {
        bail!("insertion offset {insert_at} is not an APF instruction boundary");
    }
    if let Some(b) = insns.iter().find(|i| i.target.is_some_and(|t| t < i.end)) {
        bail!(
            "backward jump at byte {} is not representable; refusing to patch",
            b.start
        );
    }
    if let Some(i) = insns
        .iter()
        .find(|i| i.target == Some(insert_at) && i.end > insert_at)
    {
        bail!(
            "jump at byte {} lands on the insertion point; refusing to patch",
            i.start
        );
    }

    let mut out = Vec::with_capacity(n + delta);
    out.extend_from_slice(&prog[..insert_at]);
    out.extend_from_slice(ins);
    out.extend_from_slice(&prog[insert_at..]);

    for i in insns.iter() {
        let Some(target) = i.target else { continue };
        // Needs +delta exactly when the instruction's own bytes stay put but its target
        // moves. PASS/DROP (n, n+1) follow the same rule — they move with program_len.
        if !(i.end <= insert_at && insert_at <= target && target <= n + 1) {
            continue;
        }
        let new = i.imm as u64 + delta as u64;
        if new >= 1u64 << (8 * i.jump_imm_len) {
            bail!(
                "jump immediate at byte {} overflows its {} byte(s) ({new}); refusing to patch",
                i.start,
                i.jump_imm_len
            );
        }
        let at = i.jump_imm_at.expect("jump with a target has an immediate");
        // Crossing jumps satisfy imm_at < end <= insert_at, so their bytes never moved.
        out[at..at + i.jump_imm_len].copy_from_slice(&new.to_be_bytes()[8 - i.jump_imm_len..]);
    }

    // Shrink the debugbuf reservation so total RAM use is unchanged.
    let dbg: Vec<&Insn> = insns
        .iter()
        .filter(|i| i.opcode == EXT && i.imm == EXCEPTIONBUFFER_EXT)
        .collect();
    if dbg.len() != 1 {
        bail!(
            "expected exactly one APF debugbuf instruction, found {}",
            dbg.len()
        );
    }
    let d = dbg[0];
    if d.end > insert_at {
        bail!(
            "APF debugbuf sits after the insertion point ({} > {insert_at})",
            d.end
        );
    }
    let at = d.end - 2;
    let size = u16::from_be_bytes(prog[at..at + 2].try_into().unwrap()) as usize;
    if size != debugbuf_size {
        bail!("debugbuf size {size} disagrees with the derived layout ({debugbuf_size})");
    }
    if size < delta {
        bail!("debugbuf {size} bytes cannot absorb the +{delta} byte insertion");
    }
    out[at..at + 2].copy_from_slice(&((size - delta) as u16).to_be_bytes());
    Ok(out)
}

/// Structural self-check on the finished program: it must walk cleanly to its own end,
/// every jump must stay in range, and our rules must decode back to what we asked for.
/// Detect our ARP insertion: N consecutive `jeq r0,<ip>,PASS` sitting between an
/// `ldw r0,[38]` and a `drop`. Returns the guest list in program order.
///
/// Unlike [`find_our_rules`] this cannot key on a vendor counter number (R1/R7 in
/// `requirements.md`): the ARP drop counter is build-specific. The `ldw r0,[38]` above the
/// run and the `drop` below it are the anchors, and since only our generator emits a run of
/// PASS-targeted 4-byte `jeq`s in that position, the shape is specific enough — the caller
/// additionally byte-compares against a freshly generated blob.
fn find_our_arp_rules(prog: &[u8], insns: &[Insn]) -> Result<Option<Vec<Ipv4Addr>>> {
    let pass = prog.len();
    for (k, drop) in insns.iter().enumerate() {
        if drop.opcode != PASSDROP || drop.reg != 1 {
            continue;
        }
        let mut ips = Vec::new();
        let mut j = k;
        while j > 0 {
            let cand = &insns[j - 1];
            if cand.opcode == JEQ && cand.reg == 0 && cand.imm_len == 4 && cand.target == Some(pass)
            {
                match cmp_imm(prog, cand) {
                    Some(v) => ips.push(Ipv4Addr::from(v)),
                    None => break,
                }
                j -= 1;
            } else {
                break;
            }
        }
        if ips.is_empty() || j == 0 {
            continue;
        }
        // The `ldw r0,[38]` is NOT necessarily adjacent to our run: the vendor's own TPA
        // comparison sits between them. Measured on prog 19 after patching:
        //
        //   151: ldw r0,[38]                    <- the anchor
        //   153: jeq r0,<own ip>,<past drop>    <- vendor's compare, not PASS-targeted
        //   162: jeq r0,<guest>,PASS            <- ours
        //   171: drop
        //
        // So allow a small gap. This is only a pre-filter; the byte comparison below against
        // a freshly generated blob is what actually decides, so widening it cannot admit a
        // false positive.
        const MAX_GAP: usize = 2;
        let anchored = insns[..j]
            .iter()
            .rev()
            .take(MAX_GAP + 1)
            .any(|i| i.opcode == LDW && i.reg == 0 && i.imm == OFF_V4_ARP_TPA);
        if anchored {
            ips.reverse();
            let want = arp_insertion_bytes(insns[j].start, prog.len(), &ips);
            if prog.get(insns[j].start..drop.start) == Some(&want[..]) {
                return Ok(Some(ips));
            }
        }
    }
    Ok(None)
}

/// Structural self-check on the finished program, for whichever sites were patched.
///
/// Replaces the old `validate()`, which always demanded the ICMP insertion and so rejected
/// an ARP-only patch — the common case in steady state (R4).
fn validate_rules(out: &[u8], want_arp: bool, want_icmp: bool, guests: &[Ipv4Addr]) -> Result<()> {
    let insns = parse(out)?;
    if insns.last().is_none_or(|i| i.end != out.len()) {
        bail!("patched program does not walk to its own length");
    }
    // The only range check in the pipeline: `program::parse` deliberately does not do one,
    // because intermediate programs between splices legitimately carry targets past their
    // own end (see the descending-splice note in `plan_stock`).
    for i in &insns {
        if let Some(t) = i.target {
            if t > out.len() + 1 {
                bail!(
                    "patched program has an out-of-range jump at byte {}",
                    i.start
                );
            }
        }
    }
    if want_arp {
        match find_our_arp_rules(out, &insns)? {
            Some(found) if found == guests => {}
            Some(found) => bail!("patched ARP rules decode to {found:?}, expected {guests:?}"),
            None => bail!("patched program does not decode back to our ARP guest pass-list"),
        }
    }
    if want_icmp {
        match find_our_rules(out, &insns)? {
            Some(found) if found == guests => {}
            Some(found) => bail!("patched ICMP rules decode to {found:?}, expected {guests:?}"),
            None => bail!("patched program does not decode back to our ICMP guest pass-list"),
        }
    }
    if !want_arp && !want_icmp {
        bail!("validate_rules called with nothing to validate");
    }
    Ok(())
}

fn validate(out: &[u8], insert_at: usize, guests: &[Ipv4Addr]) -> Result<()> {
    let insns = parse(out)?;
    if insns.last().is_none_or(|i| i.end != out.len()) {
        bail!("patched program does not walk to its own length");
    }
    for i in &insns {
        if let Some(t) = i.target {
            if t > out.len() + 1 {
                bail!(
                    "patched program has an out-of-range jump at byte {}",
                    i.start
                );
            }
        }
    }
    match find_our_rules(out, &insns)? {
        Some(found) if found == guests => Ok(()),
        Some(found) => bail!("patched program decodes to {found:?}, expected {guests:?}"),
        None => bail!("patched program does not decode back to our guest pass-list"),
    }
    .and_then(|()| {
        if insns
            .iter()
            .any(|i| i.start == insert_at && i.opcode == LDW)
        {
            Ok(())
        } else {
            bail!("patched program has no ldw at the insertion point {insert_at}")
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apf::program::debugbuf_of;

    const CURRENT_ORIG: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-current.orig.bin");
    const CURRENT_GUEST: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-guest.bin");
    const ICMP_ORIG: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-icmp.orig.bin");
    const ICMP_GUEST: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-icmp.guest.bin");
    const LIVE: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-live2.bin");
    /// Read out of firmware on warsaw 2026-09-02 (`APF_PROGRAM_ID` 19, 1183 bytes, debugbuf
    /// 561). A steady-state program: it has the vendor ARP request drop but NOT the ICMP echo
    /// drop shape, which is the combination the patcher used to fail on outright.
    const PROG19: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-prog19.bin");

    /// The site is located by following the ARP opcode dispatch, and the vendor counter it
    /// finds is 13 — not the 26 the old matcher required. Offsets cross-checked against the
    /// disassembly in `requirements.md` §1.1.
    #[test]
    fn locates_the_arp_request_site_by_dispatch_not_by_counter() {
        let insns = parse(PROG19).unwrap();
        let site = find_arp_request_drop_site(PROG19, &insns).unwrap();
        assert_eq!(
            site,
            ArpSite {
                insert_at: 162,
                counter: 13
            },
            "must land on the `drop` of the op=1 branch (151: ldw[38] / 153: jeq / 162: drop)"
        );
        // The reply branch's own non-local drop is at 147 and must NOT be chosen.
        assert_ne!(site.insert_at, 147, "the broadcast-GARP site is out of scope");
    }

    /// The regression this whole change exists for: a steady-state program has no ICMP echo
    /// drop, and that must not prevent the ARP rules from being installed.
    #[test]
    fn missing_icmp_site_no_longer_fails_the_whole_plan() {
        let insns = parse(PROG19).unwrap();
        assert!(
            find_icmp_drop_site(PROG19, &insns).is_err(),
            "fixture premise: prog 19 has no ICMP echo drop site"
        );
        let dbg = debugbuf_of(PROG19).unwrap();
        let guests = [ip("192.168.1.153")];
        let out = match plan_with_arp(PROG19, dbg, &guests).unwrap() {
            Plan::Patch(p) => p,
            Plan::AlreadyPatched => panic!("stock program cannot already be patched"),
        };
        assert_eq!(
            out.len(),
            PROG19.len() + 9,
            "one guest costs one 9-byte jeq, and no ldw (r0 already holds the TPA)"
        );
        let oi = parse(&out).unwrap();
        assert_eq!(
            find_our_arp_rules(&out, &oi).unwrap(),
            Some(vec![ip("192.168.1.153")])
        );
        assert_eq!(
            find_our_rules(&out, &oi).unwrap(),
            None,
            "no ICMP rules should have been added"
        );
    }

    /// Eight guests, the documented maximum. Checks capacity accounting and that every
    /// inserted jeq addresses PASS in the *final* program.
    #[test]
    fn arp_only_patch_scales_to_eight_guests() {
        let guests: Vec<Ipv4Addr> = (1..=8).map(|n| ip(&format!("10.0.0.{n}"))).collect();
        let dbg = debugbuf_of(PROG19).unwrap();
        let out = match plan_with_arp(PROG19, dbg, &guests).unwrap() {
            Plan::Patch(p) => p,
            Plan::AlreadyPatched => unreachable!(),
        };
        assert_eq!(out.len(), PROG19.len() + 9 * 8);
        let oi = parse(&out).unwrap();
        assert_eq!(find_our_arp_rules(&out, &oi).unwrap(), Some(guests.clone()));
        let pass = out.len();
        let ours: Vec<&Insn> = oi
            .iter()
            .filter(|i| i.opcode == JEQ && i.imm_len == 4 && i.target == Some(pass))
            .collect();
        assert_eq!(ours.len(), 8, "all eight must target PASS");
        // debugbuf shrank by exactly the insertion.
        assert_eq!(debugbuf_of(&out).unwrap(), dbg - 9 * 8);
    }

    /// No captured fixture carries both sites, so build one: splice a verbatim copy of the
    /// vendor ICMP sequence into prog 19 above the ARP site. Its internal jump targets are
    /// meaningless, which does not matter — this pins the *two-insertion arithmetic*, the part
    /// with no natural coverage and the easiest to get subtly wrong.
    fn prog19_with_an_icmp_site() -> Vec<u8> {
        let ii = parse(ICMP_ORIG).unwrap();
        let icmp_at = find_icmp_drop_site(ICMP_ORIG, &ii).unwrap();
        let k = ii.iter().position(|i| i.start == icmp_at).unwrap();
        let seq = ICMP_ORIG[ii[k - 4].start..ii[k].end].to_vec();

        // Somewhere above the ARP site (162) and on an instruction boundary.
        let pi = parse(PROG19).unwrap();
        let at = pi
            .iter()
            .find(|i| i.start > 200)
            .expect("prog 19 has instructions past 200")
            .start;
        splice(PROG19, &pi, at, &seq, debugbuf_of(PROG19).unwrap()).unwrap()
    }

    #[test]
    fn both_sites_are_patched_with_correct_final_offsets() {
        let prog = prog19_with_an_icmp_site();
        let insns = parse(&prog).unwrap();
        let arp = find_arp_request_drop_site(&prog, &insns).unwrap();
        let icmp = find_icmp_drop_site(&prog, &insns).unwrap();
        assert!(arp.insert_at < icmp, "premise: ARP is the lower site");

        let dbg = debugbuf_of(&prog).unwrap();
        let guests = [ip("192.168.1.153"), ip("192.168.1.204")];
        let out = match plan_with_arp(&prog, dbg, &guests).unwrap() {
            Plan::Patch(p) => p,
            Plan::AlreadyPatched => unreachable!(),
        };
        // ARP: 9*2. ICMP: 2 + 9*2.
        assert_eq!(out.len(), prog.len() + 18 + 20);

        let oi = parse(&out).unwrap();
        assert_eq!(
            find_our_arp_rules(&out, &oi).unwrap(),
            Some(guests.to_vec()),
            "ARP rules must decode back after the ICMP insertion shifted them"
        );
        assert_eq!(
            find_our_rules(&out, &oi).unwrap(),
            Some(guests.to_vec()),
            "ICMP rules must decode back too"
        );
        // Every one of our jeqs addresses PASS in the finished program, which is the property
        // the descending-splice order exists to preserve.
        let pass = out.len();
        assert_eq!(
            oi.iter()
                .filter(|i| i.opcode == JEQ && i.imm_len == 4 && i.target == Some(pass))
                .count(),
            4,
            "2 guests x 2 sites"
        );
    }

    /// R6: a second repatch must be a no-op, or the watchdog would grow the program on every
    /// external install. The ARP-only shape needs its own detector for this, which is why
    /// `find_our_arp_rules` exists.
    #[test]
    fn arp_only_patch_is_idempotent() {
        let dbg = debugbuf_of(PROG19).unwrap();
        let guests = [ip("192.168.1.153")];
        let once = match plan_with_arp(PROG19, dbg, &guests).unwrap() {
            Plan::Patch(p) => p,
            Plan::AlreadyPatched => unreachable!(),
        };
        assert!(
            matches!(
                plan_with_arp(&once, debugbuf_of(&once).unwrap(), &guests).unwrap(),
                Plan::AlreadyPatched
            ),
            "re-planning the same guest set must not touch the program again"
        );
    }

    /// A lease change replaces the set rather than appending to it.
    #[test]
    fn arp_only_guest_set_can_be_replaced() {
        let dbg = debugbuf_of(PROG19).unwrap();
        let first = match plan_with_arp(PROG19, dbg, &[ip("192.168.1.153")]).unwrap() {
            Plan::Patch(p) => p,
            Plan::AlreadyPatched => unreachable!(),
        };
        let second = match plan_with_arp(
            &first,
            debugbuf_of(&first).unwrap(),
            &[ip("192.168.1.7"), ip("192.168.1.9")],
        )
        .unwrap()
        {
            Plan::Patch(p) => p,
            Plan::AlreadyPatched => panic!("a different guest set must be rewritten"),
        };
        assert_eq!(
            second.len(),
            PROG19.len() + 9 * 2,
            "the previous single-guest insertion must have been removed, not kept"
        );
        let si = parse(&second).unwrap();
        assert_eq!(
            find_our_arp_rules(&second, &si).unwrap(),
            Some(vec![ip("192.168.1.7"), ip("192.168.1.9")])
        );
    }

    /// A vendor `jeq r0,<phone ip>,PASS` is byte-identical to one of our jeqs. If a build
    /// ever emits that shape, the detector would claim it as ours and strip the phone's own
    /// ARP compare. The guard in `remove_arp_rules` must refuse instead of writing that back.
    #[test]
    fn vendor_own_ip_compare_targeting_pass_is_not_stripped() {
        let insns = parse(PROG19).unwrap();
        let site = find_arp_request_drop_site(PROG19, &insns).unwrap();
        // The vendor compare is the instruction right before the drop.
        let k = insns.iter().position(|i| i.start == site.insert_at).unwrap();
        let cmp = &insns[k - 1];
        assert_eq!(cmp.opcode, JEQ);
        assert_eq!(cmp.jump_imm_len, 4);
        let mut prog = PROG19.to_vec();
        let off = (prog.len() - cmp.end) as u32;
        let at = cmp.jump_imm_at.unwrap();
        prog[at..at + 4].copy_from_slice(&off.to_be_bytes());
        let pi = parse(&prog).unwrap();
        assert_eq!(pi[k - 1].target, Some(prog.len()), "premise: now targets PASS");
        assert!(
            find_our_arp_rules(&prog, &pi).unwrap().is_some(),
            "premise: shape alone cannot tell the vendor rule from ours"
        );

        let err = plan_with_arp(&prog, debugbuf_of(&prog).unwrap(), &[ip("10.0.0.1")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("refusing to strip"), "{err}");
    }

    /// Both sites absent is the one case that must still fail, and the error has to name both
    /// reasons so the log says why.
    #[test]
    fn a_program_with_neither_site_is_refused() {
        // apf-live2 has an ICMP site; remove the ARP dispatch's reachability by using a
        // program that has neither. Build one by patching LIVE's ICMP site away is awkward,
        // so assert on the real pair instead: LIVE has no ARP site, and a program with no
        // ICMP site either must produce the combined error.
        let insns = parse(LIVE).unwrap();
        assert!(find_arp_request_drop_site(LIVE, &insns).is_err());
        assert!(find_icmp_drop_site(LIVE, &insns).is_ok());

        // Truncate the ICMP drop's counter so neither matcher fires, via the real splice path
        // so the program stays walkable: insert a copy of a harmless instruction over nothing
        // is not possible, so instead flip the drop counter byte directly and re-parse.
        let icmp_at = find_icmp_drop_site(LIVE, &insns).unwrap();
        let mut broken = LIVE.to_vec();
        let drop_insn = insns.iter().find(|i| i.start == icmp_at).unwrap();
        broken[drop_insn.imm_at] = 99; // a counter number the matcher does not look for
        let bi = parse(&broken).unwrap();
        assert!(find_icmp_drop_site(&broken, &bi).is_err());

        let err = plan_with_arp(&broken, debugbuf_of(&broken).unwrap(), &[ip("10.0.0.1")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no patchable site"), "{err}");
        assert!(err.contains("ARP:"), "must say why ARP failed: {err}");
        assert!(err.contains("ICMP:"), "must say why ICMP failed: {err}");
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn patched(prog: &[u8], guests: &[Ipv4Addr]) -> Vec<u8> {
        match plan(prog, debugbuf_of(prog).unwrap(), guests).unwrap() {
            Plan::Patch(p) => p,
            Plan::AlreadyPatched => panic!("expected a patch, got AlreadyPatched"),
        }
    }

    /// The archived ARP-branch patch: a bare 9-byte `jeq r0,<guest>,PASS` inserted at 153
    /// (reusing the already-loaded ARP target IP). Reproducing `apf-guest.bin` byte for
    /// byte proves the jump-fixup and debugbuf arithmetic against a known-good artifact —
    /// the same check `apf/tools/apf_repro_test.py` performs.
    #[test]
    fn reproduces_archived_arp_patch_byte_for_byte() {
        const INSERT_AT: usize = 153;
        let insns = parse(CURRENT_ORIG).unwrap();
        let final_len = CURRENT_ORIG.len() + JEQ_BYTES;
        let off = (final_len - (INSERT_AT + JEQ_BYTES)) as u32;
        let mut ins = vec![(JEQ << 3) | (3 << 1)];
        ins.extend_from_slice(&off.to_be_bytes());
        ins.extend_from_slice(&ip("192.168.1.204").octets());

        let dbg = debugbuf_of(CURRENT_ORIG).unwrap();
        let got = splice(CURRENT_ORIG, &insns, INSERT_AT, &ins, dbg).unwrap();
        assert_eq!(got.len(), CURRENT_GUEST.len());
        assert_eq!(
            got, CURRENT_GUEST,
            "must be byte-identical to the archived patch"
        );
    }

    /// The archived ICMP patch (`ldw r0,[30]` + one `jeq`, 11 bytes) is exactly what
    /// `plan()` generates for a single guest.
    #[test]
    fn reproduces_archived_icmp_patch_byte_for_byte() {
        let got = patched(ICMP_ORIG, &[ip("192.168.1.204")]);
        assert_eq!(got.len(), ICMP_ORIG.len() + 11, "2 + 9*1 bytes");
        assert_eq!(got.len(), ICMP_GUEST.len());
        assert_eq!(
            got, ICMP_GUEST,
            "must be byte-identical to the archived ICMP patch"
        );
    }

    #[test]
    fn patches_a_captured_live_program() {
        let got = patched(LIVE, &[ip("192.168.1.204")]);
        assert_eq!(got.len(), LIVE.len() + 11);
        // Total RAM use is unchanged: the debugbuf gave up exactly what the program took.
        assert_eq!(
            got.len() + debugbuf_of(&got).unwrap(),
            LIVE.len() + debugbuf_of(LIVE).unwrap()
        );
    }

    #[test]
    fn eight_guests_insert_74_bytes_and_all_decode_back() {
        let guests: Vec<Ipv4Addr> = (1..=8u8)
            .map(|n| Ipv4Addr::new(192, 168, 1, 200 + n))
            .collect();
        let got = patched(LIVE, &guests);
        assert_eq!(got.len(), LIVE.len() + 2 + 9 * 8, "74 bytes for 8 guests");
        let insns = parse(&got).unwrap();
        assert_eq!(find_our_rules(&got, &insns).unwrap(), Some(guests));
    }

    /// Every guest's jeq must target PASS (== program_len), not a byte inside the program.
    #[test]
    fn every_inserted_jeq_targets_pass() {
        let guests = vec![ip("10.0.0.1"), ip("10.0.0.2"), ip("10.0.0.3")];
        let got = patched(LIVE, &guests);
        let insns = parse(&got).unwrap();
        let ours: Vec<&Insn> = insns
            .iter()
            .filter(|i| i.opcode == JEQ && i.imm_len == 4 && cmp_imm(&got, i).is_some())
            .filter(|i| guests.contains(&Ipv4Addr::from(cmp_imm(&got, i).unwrap())))
            .collect();
        assert_eq!(ours.len(), 3);
        for i in ours {
            assert_eq!(
                i.target,
                Some(got.len()),
                "jeq at {} must jump to PASS",
                i.start
            );
        }
    }

    /// The live program's `jne r0,0x8,<after-drop>` ends exactly ON the insertion point:
    /// its own bytes stay put while its target moves, so it needs +delta. Getting this
    /// wrong lands non-ICMP traffic inside the inserted code.
    #[test]
    fn fixes_jump_that_ends_on_the_insertion_point() {
        let orig = parse(LIVE).unwrap();
        let site = find_icmp_drop_site(LIVE, &orig).unwrap();
        let on_boundary: Vec<&Insn> = orig
            .iter()
            .filter(|i| i.end == site && i.target.is_some())
            .collect();
        assert!(
            !on_boundary.is_empty(),
            "fixture must exercise the end == insert_at case"
        );

        let got = patched(LIVE, &[ip("192.168.1.204")]);
        for i in on_boundary {
            let after = parse(&got).unwrap();
            let same = after.iter().find(|j| j.start == i.start).unwrap();
            assert_eq!(
                same.target,
                Some(i.target.unwrap() + 11),
                "jump at {} must skip the insertion",
                i.start
            );
        }
    }

    #[test]
    fn already_patched_is_detected_and_not_rewritten() {
        let once = patched(LIVE, &[ip("192.168.1.204")]);
        let dbg = debugbuf_of(&once).unwrap();
        assert!(matches!(
            plan(&once, dbg, &[ip("192.168.1.204")]).unwrap(),
            Plan::AlreadyPatched
        ));
    }

    #[test]
    fn patched_with_a_different_guest_set_is_replaced() {
        let once = patched(LIVE, &[ip("192.168.1.204")]);
        let dbg = debugbuf_of(&once).unwrap();
        let updated = match plan(&once, dbg, &[ip("192.168.1.7")]).unwrap() {
            Plan::Patch(p) => p,
            Plan::AlreadyPatched => panic!("a different guest set must be replaced"),
        };
        let insns = parse(&updated).unwrap();
        assert_eq!(
            find_our_rules(&updated, &insns).unwrap(),
            Some(vec![ip("192.168.1.7")])
        );
        assert_eq!(
            updated.len(),
            once.len(),
            "one guest replaces one guest without growth"
        );
    }

    #[test]
    fn patched_guest_set_can_grow_and_shrink() {
        let once = patched(LIVE, &[ip("192.168.1.204")]);
        let dbg = debugbuf_of(&once).unwrap();
        let two = match plan(&once, dbg, &[ip("192.168.1.204"), ip("192.168.1.205")]).unwrap() {
            Plan::Patch(p) => p,
            _ => panic!("must replace one guest with two"),
        };
        assert_eq!(two.len(), once.len() + 9);
        let two_insns = parse(&two).unwrap();
        assert_eq!(find_our_rules(&two, &two_insns).unwrap().unwrap().len(), 2);
        let shrunk = match plan(&two, debugbuf_of(&two).unwrap(), &[ip("192.168.1.205")]).unwrap() {
            Plan::Patch(p) => p,
            _ => panic!("must replace two guests with one"),
        };
        assert_eq!(shrunk.len(), once.len());
    }

    #[test]
    fn program_without_the_drop_site_is_refused() {
        // The archived ARP-era program has no vendor ICMP drop at all.
        let dbg = debugbuf_of(CURRENT_ORIG).unwrap();
        let err = plan(CURRENT_ORIG, dbg, &[ip("192.168.1.204")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("no vendor ICMP-echo drop site"), "{err}");
    }

    /// A program carrying the vendor sequence twice is ambiguous: patching one of them
    /// would leave the other dropping echo requests, so refuse rather than guess.
    #[test]
    fn two_candidate_sites_are_refused() {
        let insns = parse(LIVE).unwrap();
        let site = find_icmp_drop_site(LIVE, &insns).unwrap();
        let k = insns.iter().position(|i| i.start == site).unwrap();
        // Splice a verbatim second copy of ldb/jne/ldb/jne/drop in through the real
        // machinery, so every crossing jump and the debugbuf stay consistent and the
        // result still walks cleanly — only the site count changes.
        let seq = LIVE[insns[k - 4].start..insns[k].end].to_vec();
        let dbg = debugbuf_of(LIVE).unwrap();
        let dup = splice(LIVE, &insns, insns[k - 4].start, &seq, dbg).unwrap();

        let dup_insns = parse(&dup).unwrap();
        let err = find_icmp_drop_site(&dup, &dup_insns)
            .unwrap_err()
            .to_string();
        assert!(err.contains("candidate ICMP-echo drop sites"), "{err}");
        // and plan() must refuse too, without producing anything to write
        assert!(plan(&dup, debugbuf_of(&dup).unwrap(), &[ip("10.0.0.1")]).is_err());
    }

    #[test]
    fn debugbuf_too_small_is_refused() {
        // Shrink the debugbuf reservation to 4 bytes: an 11-byte insertion cannot fit.
        let mut prog = LIVE.to_vec();
        let insns = parse(&prog).unwrap();
        let d = insns
            .iter()
            .find(|i| i.opcode == EXT && i.imm == EXCEPTIONBUFFER_EXT)
            .unwrap();
        let at = d.end - 2;
        prog[at..at + 2].copy_from_slice(&4u16.to_be_bytes());
        let insns = parse(&prog).unwrap();
        let site = find_icmp_drop_site(&prog, &insns).unwrap();
        let err = apply(&prog, &insns, site, 4, &[ip("192.168.1.204")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot absorb"), "{err}");
    }

    #[test]
    fn jump_immediate_overflow_is_refused() {
        // A 1-byte jump immediate at 255 cannot take +delta.
        let insns = parse(LIVE).unwrap();
        let site = find_icmp_drop_site(LIVE, &insns).unwrap();
        let victim = insns
            .iter()
            .find(|i| i.jump_imm_len == 1 && i.end <= site && i.target.is_some_and(|t| t >= site));
        let Some(v) = victim else {
            return; // fixture has no 1-byte crossing jump; nothing to assert
        };
        let mut prog = LIVE.to_vec();
        prog[v.jump_imm_at.unwrap()] = 0xff;
        let insns = match parse(&prog) {
            Ok(i) => i,
            Err(_) => return,
        };
        let dbg = debugbuf_of(&prog).unwrap();
        if let Ok(site) = find_icmp_drop_site(&prog, &insns) {
            let err = apply(&prog, &insns, site, dbg, &[ip("10.0.0.1")])
                .unwrap_err()
                .to_string();
            assert!(err.contains("overflows") || err.contains("APF"), "{err}");
        }
    }

    #[test]
    fn insertion_at_a_non_boundary_is_refused() {
        let insns = parse(LIVE).unwrap();
        let site = find_icmp_drop_site(LIVE, &insns).unwrap();
        let dbg = debugbuf_of(LIVE).unwrap();
        let err = splice(LIVE, &insns, site + 1, &[0, 0], dbg)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not an APF instruction boundary"), "{err}");
    }

    #[test]
    fn declared_debugbuf_mismatch_is_refused() {
        let insns = parse(LIVE).unwrap();
        let site = find_icmp_drop_site(LIVE, &insns).unwrap();
        let wrong = debugbuf_of(LIVE).unwrap() - 1;
        let err = apply(LIVE, &insns, site, wrong, &[ip("10.0.0.1")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("disagrees with the derived layout"), "{err}");
    }

    /// Only the inserted instructions may differ; everything else is the same instruction
    /// stream, shifted. This is the Rust equivalent of `apf/tools/apf_verify_shift.py`.
    #[test]
    fn nothing_but_the_insertion_changes() {
        let guests = vec![ip("192.168.1.204"), ip("192.168.1.7")];
        let got = patched(LIVE, &guests);
        let before = parse(LIVE).unwrap();
        let after = parse(&got).unwrap();
        let delta = 2 + 9 * guests.len();
        let site = find_icmp_drop_site(LIVE, &before).unwrap();
        assert_eq!(
            after.len(),
            before.len() + 1 + guests.len(),
            "only ldw + N jeq are new"
        );

        for b in &before {
            let shift = if b.start >= site { delta } else { 0 };
            let a = after
                .iter()
                .find(|a| a.start == b.start + shift)
                .unwrap_or_else(|| panic!("instruction from {} vanished", b.start));
            assert_eq!(a.opcode, b.opcode, "opcode changed at {}", b.start);
            assert_eq!(a.reg, b.reg, "register changed at {}", b.start);
            assert_eq!(
                a.end - a.start,
                b.end - b.start,
                "length changed at {}",
                b.start
            );
            match (b.target, a.target) {
                (None, None) => {}
                (Some(bt), Some(at)) => {
                    // A target below the site is untouched; one at or past it shifts.
                    let want = if bt >= site { bt + delta } else { bt };
                    assert_eq!(at, want, "target changed unexpectedly at {}", b.start);
                }
                _ => panic!("jump-ness changed at {}", b.start),
            }
        }
    }
}
