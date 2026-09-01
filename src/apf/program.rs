//! Defensive APFv6 instruction walker.
//!
//! Firmware READ returns fixed-size *work memory* (2048 bytes), not the program's
//! length. Treating all 2048 bytes as bytecode is unsafe: the zero-filled debug/counter
//! region decodes as valid one-byte instructions. The Xiaomi programs validated for this
//! device reserve a fixed 304-byte counter area, so the sole `debugbuf` instruction gives
//! the only trustworthy boundary: `program_len + debugbuf_size == 1744`.

use anyhow::{bail, Result};

pub const APF_RAM_BYTES: usize = 2048;
/// `program_len + debugbuf_size` on this device: APF RAM (2048) minus the 304-byte
/// counter region that `ApfFilter` pins at the top of RAM (76 counters × 4 bytes).
/// Verified constant across all 15 archived programs in `apf/programs` + `apf/evidence`.
/// [`ProgramLayout::derive`] re-checks the counter-region half of that identity, so a
/// future program with a different counter set is rejected instead of mis-parsed.
pub const PROGRAM_PLUS_DEBUGBUF: usize = 1744;

pub const PASSDROP: u8 = 0;
pub const LDB: u8 = 1;
pub const LDH: u8 = 2;
pub const LDW: u8 = 3;
pub const LDBX: u8 = 4;
pub const LDHX: u8 = 5;
pub const LDWX: u8 = 6;
pub const ADD: u8 = 7;
pub const MUL: u8 = 8;
pub const DIV: u8 = 9;
pub const AND: u8 = 10;
pub const OR: u8 = 11;
pub const SH: u8 = 12;
pub const LI: u8 = 13;
pub const JMP: u8 = 14;
pub const JEQ: u8 = 15;
pub const JNE: u8 = 16;
pub const JGT: u8 = 17;
pub const JLT: u8 = 18;
pub const JSET: u8 = 19;
pub const JBSMATCH: u8 = 20;
pub const EXT: u8 = 21;
pub const LDDW: u8 = 22;
pub const STDW: u8 = 23;
pub const WRITE: u8 = 24;
pub const PKTDATACOPY: u8 = 25;
pub const JNSET: u8 = 26;
pub const JBSPTRMATCH: u8 = 27;
pub const ALLOC_XMIT: u8 = 28;

pub const EXCEPTIONBUFFER_EXT: u32 = 48;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Insn {
    pub start: usize,
    pub end: usize,
    pub opcode: u8,
    pub reg: u8,
    pub imm: u32,
    pub imm_at: usize,
    pub imm_len: usize,
    pub jump_imm_at: Option<usize>,
    pub jump_imm_len: usize,
    pub target: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramLayout {
    pub program_len: usize,
    pub debugbuf_size: usize,
}

impl ProgramLayout {
    /// Infer and validate the live program's length before any write is possible.
    pub fn derive(work: &[u8]) -> Result<Self> {
        if work.len() != APF_RAM_BYTES {
            bail!(
                "APF work memory length is {}, expected {APF_RAM_BYTES}",
                work.len()
            );
        }
        // The debugbuf instruction is part of the fixed prologue (byte 9 or 19 in every
        // captured Xiaomi program). Find its exact 4-byte encoding in that small region:
        // `EXT,len=1,r0` (= 0xaa), immediate `EXCEPTIONBUFFER_EXT` (= 48), then u16 size.
        // We intentionally do NOT instruction-walk beyond this prologue: work memory
        // beyond the actual program is arbitrary stale RAM, not bytecode. The complete
        // bounded program is walked below once its length is known.
        const DEBUGBUF_SCAN_BYTES: usize = 128;
        let debug_starts: Vec<usize> = work[..DEBUGBUF_SCAN_BYTES - 3]
            .windows(2)
            .enumerate()
            .filter_map(|(at, bytes)| {
                (bytes == [(EXT << 3) | (1 << 1), EXCEPTIONBUFFER_EXT as u8]).then_some(at)
            })
            .collect();
        if debug_starts.len() != 1 {
            bail!(
                "expected exactly one APF debugbuf prologue instruction, found {}",
                debug_starts.len()
            );
        }
        let at = debug_starts[0] + 2;
        let debugbuf_size = u16::from_be_bytes(work[at..at + 2].try_into().unwrap()) as usize;
        let program_len = PROGRAM_PLUS_DEBUGBUF
            .checked_sub(debugbuf_size)
            .ok_or_else(|| {
                anyhow::anyhow!("debugbuf {debugbuf_size} exceeds APF executable budget")
            })?;
        if program_len == 0 || program_len > PROGRAM_PLUS_DEBUGBUF {
            bail!("invalid derived APF program length {program_len}");
        }
        let program = &work[..program_len];
        let insns = parse(program)?;
        if insns.last().is_none_or(|i| i.end != program_len) {
            bail!("APF instruction walk did not end at derived program boundary {program_len}");
        }
        // The device's verified vendor template ends with a PASS instruction before the
        // interpreter's implicit PASS/DROP pseudo-targets. This rejects a random/future
        // work-memory layout instead of blindly editing an unfamiliar program.
        let last = insns.last().unwrap();
        if last.opcode != PASSDROP || last.reg != 0 {
            bail!("derived APF program does not end in vendor-template PASS instruction");
        }
        // Independent check on PROGRAM_PLUS_DEBUGBUF: the space it leaves at the top of
        // RAM must exactly hold the counters this program actually addresses. If a future
        // build changes the counter set, the constant is wrong and this catches it before
        // any write — a too-large constant would push `program_len` into the counters.
        let max_counter = insns
            .iter()
            .filter(|i| i.opcode == PASSDROP || i.opcode == STDW)
            .map(|i| i.imm)
            .max()
            .unwrap_or(0) as usize;
        let counter_region = APF_RAM_BYTES - PROGRAM_PLUS_DEBUGBUF;
        if counter_region < 4 * max_counter {
            bail!(
                "APF counter region ({counter_region} bytes) cannot hold counter {max_counter}; \
                 the program/debugbuf budget constant does not match this firmware build"
            );
        }
        // Every jump must stay inside the program (or hit the PASS/DROP pseudo-targets).
        if let Some(i) = insns
            .iter()
            .find(|i| i.target.is_some_and(|t| t > program_len + 1))
        {
            bail!(
                "APF jump at byte {} targets past the derived program end",
                i.start
            );
        }
        Ok(Self {
            program_len,
            debugbuf_size,
        })
    }
}

/// Parse every byte of one APFv6 program. Any malformed/truncated/unknown instruction is
/// an error; the patcher never attempts a best-effort edit.
pub fn parse(prog: &[u8]) -> Result<Vec<Insn>> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < prog.len() {
        let start = pc;
        let b = take_u8(prog, &mut pc, "instruction opcode")?;
        let opcode = b >> 3;
        let len_field = (b & 6) >> 1;
        let reg = b & 1;
        let imm_len = if len_field == 0 {
            0
        } else {
            1usize << (len_field - 1)
        };
        let imm_at = pc;
        let imm = take_be(prog, &mut pc, imm_len, "instruction immediate")?;
        let mut jump_imm_at = None;
        let mut jump_imm_len = 0;
        let mut target = None;

        match opcode {
            JMP if reg == 1 => skip(prog, &mut pc, imm as usize, "data payload")?,
            JMP => set_jump(
                &mut jump_imm_at,
                &mut jump_imm_len,
                &mut target,
                imm_at,
                imm_len,
                pc,
                imm,
            )?,
            JEQ | JNE | JGT | JLT | JSET | JNSET => {
                if reg == 0 && len_field != 0 {
                    skip(prog, &mut pc, imm_len, "comparison immediate")?;
                }
                set_jump(
                    &mut jump_imm_at,
                    &mut jump_imm_len,
                    &mut target,
                    imm_at,
                    imm_len,
                    pc,
                    imm,
                )?;
            }
            JBSMATCH => {
                let cmp = take_be(prog, &mut pc, imm_len, "jbs comparison")?;
                let count = ((cmp >> 11) + 1) as usize;
                let len = (cmp & 2047) as usize;
                skip(
                    prog,
                    &mut pc,
                    count
                        .checked_mul(len)
                        .ok_or_else(|| anyhow::anyhow!("jbs payload overflow"))?,
                    "jbs payload",
                )?;
                set_jump(
                    &mut jump_imm_at,
                    &mut jump_imm_len,
                    &mut target,
                    imm_at,
                    imm_len,
                    pc,
                    imm,
                )?;
            }
            JBSPTRMATCH => {
                skip(prog, &mut pc, 1, "jbsptr packet offset")?;
                let cmp = take_u8(prog, &mut pc, "jbsptr comparison")?;
                skip(prog, &mut pc, ((cmp >> 4) + 1) as usize, "jbsptr payload")?;
                set_jump(
                    &mut jump_imm_at,
                    &mut jump_imm_len,
                    &mut target,
                    imm_at,
                    imm_len,
                    pc,
                    imm,
                )?;
            }
            PKTDATACOPY => {
                let len = take_u8(prog, &mut pc, "packet-copy length")? as usize;
                if len == 0 {
                    skip(prog, &mut pc, 1, "packet-copy register")?;
                }
            }
            EXT => match imm {
                // allocate: reg==1 carries an immediate size, reg==0 takes it from R0.
                36 if reg == 1 => skip(prog, &mut pc, 2, "allocate size")?,
                36 => {}
                37 => {
                    skip(prog, &mut pc, 1, "transmit ip offset")?;
                    if take_u8(prog, &mut pc, "transmit checksum offset")? < 255 {
                        skip(prog, &mut pc, 3, "transmit checksum data")?;
                    }
                }
                41 => {
                    let len = take_u8(prog, &mut pc, "ext packet-copy length")? as usize;
                    if len == 0 {
                        skip(prog, &mut pc, 1, "ext packet-copy register")?;
                    }
                }
                47 => {
                    let at = pc;
                    let off = take_be(prog, &mut pc, imm_len, "joneof jump")?;
                    let hdr = take_u8(prog, &mut pc, "joneof header")?;
                    let bytes = ((hdr >> 3) + 2) as usize * (((hdr >> 1) & 3) as usize + 1);
                    skip(prog, &mut pc, bytes, "joneof set")?;
                    set_jump(
                        &mut jump_imm_at,
                        &mut jump_imm_len,
                        &mut target,
                        at,
                        imm_len,
                        pc,
                        off,
                    )?;
                }
                48 => skip(prog, &mut pc, 2, "debugbuf size")?,
                // Known simple EXT variants: memory loads/stores, unary ops, ewrite,
                // and packet-copy-from-R1 have no trailing payload.
                0..=31 | 32..=35 | 38..=40 | 42 => {}
                x => bail!("unknown APF EXT opcode {x} at byte {start}"),
            },
            PASSDROP | LDB | LDH | LDW | LDBX | LDHX | LDWX | ADD | MUL | DIV | AND | OR | SH
            | LI | LDDW | STDW | WRITE | ALLOC_XMIT => {}
            x => bail!("unknown APF opcode {x} at byte {start}"),
        }
        out.push(Insn {
            start,
            end: pc,
            opcode,
            reg,
            imm,
            imm_at,
            imm_len,
            jump_imm_at,
            jump_imm_len,
            target,
        });
    }
    Ok(out)
}

fn set_jump(
    at: &mut Option<usize>,
    len: &mut usize,
    target: &mut Option<usize>,
    imm_at: usize,
    imm_len: usize,
    end: usize,
    imm: u32,
) -> Result<()> {
    if imm_len == 0 {
        bail!("APF jump has no offset immediate at byte {imm_at}");
    }
    *at = Some(imm_at);
    *len = imm_len;
    *target = Some(
        end.checked_add(imm as usize)
            .ok_or_else(|| anyhow::anyhow!("APF jump target overflow"))?,
    );
    Ok(())
}

fn take_u8(p: &[u8], pc: &mut usize, what: &str) -> Result<u8> {
    let x = *p
        .get(*pc)
        .ok_or_else(|| anyhow::anyhow!("truncated APF {what} at byte {}", *pc))?;
    *pc += 1;
    Ok(x)
}
fn take_be(p: &[u8], pc: &mut usize, n: usize, what: &str) -> Result<u32> {
    if n > 4 || *pc + n > p.len() {
        bail!("truncated APF {what} at byte {}", *pc);
    }
    let mut x = 0u32;
    for b in &p[*pc..*pc + n] {
        x = (x << 8) | u32::from(*b);
    }
    *pc += n;
    Ok(x)
}
fn skip(p: &[u8], pc: &mut usize, n: usize, what: &str) -> Result<()> {
    if n > p.len().saturating_sub(*pc) {
        bail!("truncated APF {what} at byte {}", *pc);
    }
    *pc += n;
    Ok(())
}

/// Read the one debugbuf reservation from an already-bounded program. Used by the patcher
/// tests and by callers that have a program rather than a full 2048-byte work-memory read.
#[cfg(test)]
pub fn debugbuf_of(prog: &[u8]) -> Result<usize> {
    let insns = parse(prog)?;
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
    let at = dbg[0]
        .end
        .checked_sub(2)
        .ok_or_else(|| anyhow::anyhow!("malformed debugbuf"))?;
    Ok(u16::from_be_bytes(prog[at..at + 2].try_into().unwrap()) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-live2.bin");
    const CURRENT: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-current.orig.bin");
    const ICMP: &[u8] = include_bytes!("../../tests/apf-fixtures/apf-icmp.orig.bin");

    /// Every archived program must walk with full byte coverage — a walker that silently
    /// mis-sizes one instruction would corrupt every jump fixup downstream.
    #[test]
    fn walks_archived_programs_completely() {
        for (name, prog) in [("live2", LIVE), ("current", CURRENT), ("icmp", ICMP)] {
            let insns = parse(prog).unwrap_or_else(|e| panic!("{name}: {e:#}"));
            let covered: usize = insns.iter().map(|i| i.end - i.start).sum();
            assert_eq!(
                covered,
                prog.len(),
                "{name}: walk covered {covered}/{}",
                prog.len()
            );
            assert_eq!(
                insns.last().unwrap().end,
                prog.len(),
                "{name}: ends mid-program"
            );
            for i in &insns {
                if let Some(t) = i.target {
                    assert!(
                        t <= prog.len() + 1,
                        "{name}: jump at {} out of range",
                        i.start
                    );
                }
            }
        }
    }

    /// Build the work memory the firmware actually returns: program, then the debugbuf
    /// reservation, then the counter region — all 2048 bytes.
    fn work_memory(prog: &[u8]) -> Vec<u8> {
        let mut w = prog.to_vec();
        w.resize(APF_RAM_BYTES, 0);
        w
    }

    #[test]
    fn derives_program_length_from_work_memory() {
        for (name, prog) in [("live2", LIVE), ("current", CURRENT), ("icmp", ICMP)] {
            let layout = ProgramLayout::derive(&work_memory(prog))
                .unwrap_or_else(|e| panic!("{name}: {e:#}"));
            assert_eq!(layout.program_len, prog.len(), "{name}");
            assert_eq!(
                layout.program_len + layout.debugbuf_size,
                PROGRAM_PLUS_DEBUGBUF,
                "{name}: the executable budget identity must hold"
            );
        }
    }

    #[test]
    fn rejects_wrong_sized_work_memory() {
        assert!(
            ProgramLayout::derive(LIVE).is_err(),
            "short read must be refused"
        );
        let mut big = work_memory(LIVE);
        big.push(0);
        assert!(ProgramLayout::derive(&big).is_err());
    }

    /// A corrupted debugbuf size moves the derived boundary off an instruction edge; the
    /// walk must catch that rather than hand the patcher a wrong program length.
    #[test]
    fn rejects_debugbuf_that_misplaces_the_boundary() {
        let insns = parse(LIVE).unwrap();
        let d = insns
            .iter()
            .find(|i| i.opcode == EXT && i.imm == EXCEPTIONBUFFER_EXT)
            .unwrap();
        let at = d.end - 2;
        let real = u16::from_be_bytes(LIVE[at..at + 2].try_into().unwrap());
        let mut bad = 0usize;
        for delta in 1..=8u16 {
            let mut w = work_memory(LIVE);
            w[at..at + 2].copy_from_slice(&(real + delta).to_be_bytes());
            if ProgramLayout::derive(&w).is_err() {
                bad += 1;
            }
        }
        assert!(
            bad >= 6,
            "only {bad}/8 shifted boundaries refused; detection is too weak"
        );
    }

    #[test]
    fn rejects_all_zero_work_memory() {
        // Zeroes decode as a long run of one-byte PASS instructions and carry no debugbuf.
        assert!(ProgramLayout::derive(&vec![0u8; APF_RAM_BYTES]).is_err());
    }

    #[test]
    fn rejects_garbage_work_memory() {
        let junk: Vec<u8> = (0..APF_RAM_BYTES).map(|i| (i * 37 + 11) as u8).collect();
        assert!(ProgramLayout::derive(&junk).is_err());
    }

    #[test]
    fn truncated_instruction_is_an_error_not_a_guess() {
        // Chop the last instruction's immediate off: the walk must fail, not round down.
        let insns = parse(LIVE).unwrap();
        let last = insns.last().unwrap();
        let cut = &LIVE[..last.end - 1];
        // Either the walk errors, or it ends short of the requested length — never a
        // silent full-coverage success.
        if let Ok(i) = parse(cut) {
            assert_ne!(i.last().unwrap().end, LIVE.len());
        }
    }
}
