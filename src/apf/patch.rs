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
    parse, Insn, EXCEPTIONBUFFER_EXT, EXT, JEQ, JNE, LDB, LDW, PASSDROP, PROGRAM_PLUS_DEBUGBUF,
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
    let (stock, stock_insns, stock_dbg) = if let Some(found) = find_our_rules(prog, &insns)? {
        let stock = remove_our_rules(prog, &insns, &found)?;
        let parsed = parse(&stock)?;
        let dbg = debugbuf_size_of(&stock, &parsed)?;
        (stock, parsed, dbg)
    } else {
        (prog.to_vec(), insns, debugbuf_size)
    };
    plan_stock(&stock, &stock_insns, stock_dbg, guests)
}

fn plan_stock(
    prog: &[u8],
    insns: &[Insn],
    debugbuf_size: usize,
    guests: &[Ipv4Addr],
) -> Result<Plan> {
    // With guest /32 proxies removed, NetworkStack normally emits the vendor ARP
    // "other host" drop (counter 26), which we patch precisely by TPA. Some historical
    // programs (including the old proxy-address layout) already pass ARP and have no
    // such site; preserve their proven ICMP-only patch shape instead of failing.
    let (arp_patched, arp_insns, arp_dbg) = match find_arp_drop_site(insns) {
        Ok(arp_at) => {
            // The ARP jeqs target the final program PASS. They are inserted before the
            // ICMP insertion, so account for BOTH deltas now; `apply()` will then shift
            // their crossing jump offsets when it inserts the ICMP block later.
            let total_delta = JEQ_BYTES * guests.len() + LDW_BYTES + JEQ_BYTES * guests.len();
            let arp = arp_insertion_bytes(arp_at, prog.len() + total_delta, guests);
            let patched = splice(prog, insns, arp_at, &arp, debugbuf_size)?;
            let parsed = parse(&patched)?;
            let dbg = debugbuf_size_of(&patched, &parsed)?;
            (patched, parsed, dbg)
        }
        Err(e)
            if e.to_string()
                .starts_with("no vendor ARP non-local drop site") =>
        {
            (prog.to_vec(), insns.to_vec(), debugbuf_size)
        }
        Err(e) => return Err(e),
    };
    let icmp_at = find_icmp_drop_site(&arp_patched, &arp_insns)?;
    Ok(Plan::Patch(apply(
        &arp_patched,
        &arp_insns,
        icmp_at,
        arp_dbg,
        guests,
    )?))
}

fn find_arp_drop_site(insns: &[Insn]) -> Result<usize> {
    let sites: Vec<usize> = insns
        .windows(3)
        .filter_map(|w| {
            let (load, jne, drop) = (&w[0], &w[1], &w[2]);
            (load.opcode == LDW
                && load.reg == 0
                && load.imm == OFF_V4_ARP_TPA
                && jne.opcode == JNE
                && jne.reg == 0
                && jne.imm_len > 0
                && drop.opcode == PASSDROP
                && drop.reg == 1
                && drop.imm == 26)
                .then_some(drop.start)
        })
        .collect();
    match sites.as_slice() {
        [site] => Ok(*site),
        [] => bail!("no vendor ARP non-local drop site (ldw[38]/jne/drop counter=26)"),
        _ => bail!("{} candidate vendor ARP non-local drop sites", sites.len()),
    }
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

fn remove_arp_rules(prog: &[u8], insns: &[Insn], guests: &[Ipv4Addr]) -> Result<Vec<u8>> {
    let pass = prog.len();
    let mut range = None;
    for (k, drop) in insns.iter().enumerate() {
        if drop.opcode != PASSDROP || drop.reg != 1 || drop.imm != 26 {
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
        ips.reverse();
        if ips == guests {
            range = Some((insns[j].start, drop.start));
            break;
        }
    }
    let Some((start, end)) = range else {
        bail!("cannot locate the byte-identical pbridge ARP insertion to replace");
    };
    remove_insertion(prog, insns, start, end)
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
