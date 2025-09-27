// Counter (Minsky) Machine with XOR-by-imm implemented in the machine language itself.
// No wasm, pure Rust. Runs with `cargo run`.
//
// ISA:
//   INC r
//   DECJZ r, jz, jnz   // if r==0 -> pc=jz; else r--, pc=jnz
//   JMP to
//   OUT r              // output low 8 bits of r
//   HALT
//
// We build a program that: for each byte c in CIPHERTEXT and k in KEY,
//   r0 := c
//   r0 ^= k         (performed using only counter primitives)
//   OUT r0
// which prints the plaintext flag.
//
// Registers used by the XOR subroutines:
//   r0 : accumulator byte (0..255)
//   r1 : quotient / general tmp
//   r2 : parity bit (0/1) when halving; doubles as "current bit" storage
//   r3..r10 : b0..b7 bit registers (0/1)
//   r11 : scratch during rebuild/doubling
//
// The helpers emit *only* INC / DECJZ / JMP / OUT / HALT.

use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Serialize, Deserialize, Clone, Debug)]
enum Instr {
    Inc { r: usize },
    DecJz { r: usize, jz: usize, jnz: usize },
    Jmp { to: usize },
    Out { r: usize },
    Halt,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Program {
    code: Vec<Instr>,
}

#[derive(Clone, Debug)]
struct Machine {
    counters: Vec<u128>,
    pc: usize,
    halted: bool,
    output: Vec<u8>,
    prog: Program,
    step_limit: Option<u64>,
}

impl Machine {
    fn new(num_counters: usize, prog: Program) -> Self {
        Self {
            counters: vec![0; num_counters],
            pc: 0,
            halted: false,
            output: Vec::new(),
            prog,
            step_limit: Some(50_000_000), // generous but safe
        }
    }
    fn run(&mut self) {
        let mut steps: u64 = 0;
        while !self.halted && self.pc < self.prog.code.len() {
            if let Some(limit) = self.step_limit {
                if steps >= limit {
                    panic!("step limit reached ({}). probable infinite loop.", limit);
                }
            }
            steps += 1;
            match self.prog.code[self.pc].clone() {
                Instr::Inc { r } => {
                    self.counters[r] = self.counters[r].wrapping_add(1);
                    self.pc += 1;
                }
                Instr::DecJz { r, jz, jnz } => {
                    if self.counters[r] == 0 {
                        self.pc = jz;
                    } else {
                        self.counters[r] -= 1;
                        self.pc = jnz;
                    }
                }
                Instr::Jmp { to } => {
                    self.pc = to;
                }
                Instr::Out { r } => {
                    self.output.push((self.counters[r] & 0xFF) as u8);
                    self.pc += 1;
                }
                Instr::Halt => {
                    self.halted = true;
                }
            }
        }
    }
}

struct Asm {
    code: Vec<Instr>,
}

impl Asm {
    fn new() -> Self {
        Self { code: Vec::new() }
    }
    fn pos(&self) -> usize {
        self.code.len()
    }
    fn emit(&mut self, i: Instr) -> usize {
        let p = self.code.len();
        self.code.push(i);
        p
    }
    fn inc(&mut self, r: usize) {
        self.emit(Instr::Inc { r });
    }
    fn jmp(&mut self, to: usize) {
        self.emit(Instr::Jmp { to });
    }
    fn out(&mut self, r: usize) {
        self.emit(Instr::Out { r });
    }
    fn halt(mut self) -> Program {
        self.emit(Instr::Halt);
        Program { code: self.code }
    }

    // Emit a DECJZ with placeholder targets, return its index for backpatch.
    fn decjz_placeholder(&mut self, r: usize) -> usize {
        self.emit(Instr::DecJz { r, jz: 0, jnz: 0 })
    }
    fn patch_decjz(&mut self, at: usize, jz: usize, jnz: usize) {
        match &mut self.code[at] {
            Instr::DecJz {
                r: _,
                jz: pjz,
                jnz: pjnz,
            } => {
                *pjz = jz;
                *pjnz = jnz;
            }
            _ => unreachable!("not a DecJz"),
        }
    }

    // zero(r): while r>0 { r-- }
    fn zero(&mut self, r: usize) {
        let loop_i = self.decjz_placeholder(r);
        let after = self.pos();
        self.patch_decjz(loop_i, after, loop_i);
    }

    // transfer(src -> dst): while src>0 { src--; dst++; }
    fn transfer(&mut self, src: usize, dst: usize) {
        let loop_i = self.decjz_placeholder(src);
        // on zero: after
        let cont = self.pos();
        self.inc(dst);
        self.jmp(loop_i);
        let after = self.pos();
        self.patch_decjz(loop_i, after, cont);
    }

    // toggle_bit(bit_reg, &mut q_reg): if bit==0 -> set to 1; else (==1) -> set to 0 and q++
    // uses only DECJZ/INC/JMP, leaves bit in {0,1}
    fn toggle_bit_and_maybe_inc(&mut self, bit: usize, q_on_1: usize) {
        // Test bit via DECJZ
        let test = self.decjz_placeholder(bit);
        // Case bit==0: set to 1
        let case_zero = self.pos();
        self.inc(bit);
        let join = self.pos();
        self.jmp(0); // placeholder to join

        // Case bit>0: (we already decremented, so it is 0 now) -> inc q_on_1
        let case_one = self.pos();
        self.inc(q_on_1);
        // fallthrough to after
        let after = self.pos();

        // Patch branches
        // test: if zero -> jz=case_zero; else jnz=case_one
        self.patch_decjz(test, case_zero, case_one);
        // patch the join jump to after
        if let Instr::Jmp { to } = &mut self.code[join] {
            *to = after;
        } else {
            unreachable!();
        }
    }

    // halve(src -> q, with remainder in rem_bit (0/1)) using parity toggling
    //   q = floor(src/2), rem_bit = src % 2
    // destroys src; leaves src==0
    fn halve_to_q_and_rem(&mut self, src: usize, q: usize, rem_bit: usize) {
        // rem_bit := 0; q := 0
        self.zero(rem_bit);
        self.zero(q);

        // loop: while src>0 { src--; toggle rem; if rem became 0 -> q++ }
        let loop_i = self.decjz_placeholder(src);
        let cont = self.pos();

        // toggle rem: if rem==0 -> set 1; else (was 1) -> set 0 and q++
        self.toggle_bit_and_maybe_inc(rem_bit, q);

        self.jmp(loop_i);
        let after = self.pos();
        self.patch_decjz(loop_i, after, cont);
    }

    // double(dst) using tmp: dst := 2*dst; tmp is clobbered
    fn double(&mut self, dst: usize, tmp: usize) {
        // tmp := 0; move dst -> tmp; while tmp>0 { tmp--; dst+=2 }
        self.zero(tmp);
        // move dst->tmp
        let loop1 = self.decjz_placeholder(dst);
        let cont1 = self.pos();
        self.inc(tmp);
        self.jmp(loop1);
        let after1 = self.pos();
        self.patch_decjz(loop1, after1, cont1);

        // while tmp>0 { tmp--; dst+=2 }
        let loop2 = self.decjz_placeholder(tmp);
        let cont2 = self.pos();
        self.inc(dst);
        self.inc(dst);
        self.jmp(loop2);
        let after2 = self.pos();
        self.patch_decjz(loop2, after2, cont2);
    }

    // r ^= imm (byte) implemented entirely with counters:
    // 1) extract bits of r into b0..b7 via repeated halving
    // 2) for each i where imm bit is 1, toggle b[i]
    // 3) rebuild r from bits: r = 0; for i=7..0 { r*=2; if b[i]==1 then r++ (and clear b[i]) }
    fn xor_imm_byte(
        &mut self,
        r: usize,
        imm: u8,
        q: usize,
        rem: usize,
        bits: [usize; 8],
        tmp: usize,
    ) {
        // Step 1: extract bits
        // We repeatedly halve r: each halve yields LSB into `rem`, quotient in `q`.
        // We store each remainder into bits[i] (0/1), then move q->r for next round.
        for i in 0..8 {
            self.halve_to_q_and_rem(r, q, rem);
            // move rem -> bits[i]  (rem is 0/1)
            self.zero(bits[i]);
            // copy rem into bits[i] (and clear rem)
            let test = self.decjz_placeholder(rem);
            let case_zero = self.pos(); // rem==0 -> nothing
            let join_j = self.emit(Instr::Jmp { to: 0 });
            let case_one = self.pos(); // rem>0 -> set bits[i]=1 (rem already 0 after dec)
            self.inc(bits[i]);
            let after = self.pos();
            self.patch_decjz(test, case_zero, case_one);
            if let Instr::Jmp { to } = &mut self.code[join_j] {
                *to = after;
            } else {
                unreachable!();
            }

            // q -> r (prepare for next bit)
            self.zero(r);
            self.transfer(q, r);
        }

        // Step 2: toggle selected bits according to imm
        for i in 0..8 {
            if ((imm >> i) & 1) == 1 {
                // toggle bits[i]
                // Use toggle_bit_and_maybe_inc with q as a dummy counter to increment when bit was 1
                self.toggle_bit_and_maybe_inc(bits[i], q);
                // q was incremented if bit was 1; zero it again (we don't care about the count)
                self.zero(q);
            }
        }

        // Step 3: rebuild r from bits (MSB..LSB)
        self.zero(r);
        for i in (0..8).rev() {
            self.double(r, tmp);
            // if bits[i]==1 then r++ and clear bits[i]
            let test = self.decjz_placeholder(bits[i]);
            let case_zero = self.pos(); // 0 -> nothing
            let join = self.emit(Instr::Jmp { to: 0 });
            let case_one = self.pos(); // >0 after dec -> now zero; add 1 to r
            self.inc(r);
            let after = self.pos();
            self.patch_decjz(test, case_zero, case_one);
            if let Instr::Jmp { to } = &mut self.code[join] {
                *to = after;
            } else {
                unreachable!();
            }
        }
    }
}

fn main() {
    let prog = build_flag_prog();
    let binary = bincode::serialize(&prog).unwrap();
    let mut m = Machine::new(16, prog);
    m.run();
    assert_eq!(
        String::from_utf8(m.output).unwrap(),
        "FortID{w38_4nd_81n4ry_4r3_900d_c0up13_4nd_y0u_c4n_d0_50m3_c001_4nd_57r4n93_57uff}"
    );
    fs::write("out.bin", &binary).unwrap(); // writes raw bytes
}

fn build_flag_prog() -> Program {
    // Example data. Replace with your own.
    // FLAG: "CTF{xor_on_counters_only!}"
    // KEY:  a simple repeating key (e.g., 0xA5)
    const FLAG: &str =
        "FortID{w38_4nd_81n4ry_4r3_900d_c0up13_4nd_y0u_c4n_d0_50m3_c001_4nd_57r4n93_57uff}";
    const KEY_BYTE: u8 = 0xA5;

    // Prepare ciphertext = flag ^ KEY_BYTE
    let ciphertext: Vec<u8> = FLAG.bytes().map(|b| b ^ KEY_BYTE).collect();

    // Register layout (see comments in xor_imm_byte):
    let r: usize = 0; // accumulator byte
    let q: usize = 1; // quotient tmp
    let rem: usize = 2; // remainder/parity bit
    let b0: usize = 3;
    let b1: usize = 4;
    let b2: usize = 5;
    let b3: usize = 6;
    let b4: usize = 7;
    let b5: usize = 8;
    let b6: usize = 9;
    let b7: usize = 10;
    let tmp: usize = 11; // doubling temp

    let mut a = Asm::new();

    for &c in &ciphertext {
        // r := c
        a.zero(r);
        for _ in 0..c {
            a.inc(r);
        }

        // r ^= KEY_BYTE (inside the machine)
        a.xor_imm_byte(r, KEY_BYTE, q, rem, [b0, b1, b2, b3, b4, b5, b6, b7], tmp);

        // OUT r
        a.out(r);

        // (Optional) wipe temps (not necessary for correctness, but tidy)
        a.zero(q);
        a.zero(rem);
        a.zero(b0);
        a.zero(b1);
        a.zero(b2);
        a.zero(b3);
        a.zero(b4);
        a.zero(b5);
        a.zero(b6);
        a.zero(b7);
        a.zero(tmp);
    }

    a.halt()
}
