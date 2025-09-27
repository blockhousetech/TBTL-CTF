use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use web_sys::window;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Serialize, Deserialize)]
enum Instr {
    Inc { r: usize },
    DecJz { r: usize, jz: usize, jnz: usize },
    Jmp { to: usize },
    Out { r: usize },
    Halt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Program {
    code: Vec<Instr>,
}

#[derive(Clone, Debug)]
struct Machine {
    counters: Vec<u128>,
    pc: usize,
    halted: bool,
    output: Zeroizing<Vec<u8>>,
    prog: Program,
    step_limit: Option<u64>,
}

impl Machine {
    fn new(num_counters: usize, prog: Program) -> Self {
        Self {
            counters: vec![0; num_counters],
            pc: 0,
            halted: false,
            output: Zeroizing::new(Vec::new()),
            prog,
            step_limit: Some(50_000_000), // safety cap
        }
    }
    fn run(&mut self) {
        let mut steps: u64 = 0;
        while !self.halted && self.pc < self.prog.code.len() {
            if let Some(limit) = self.step_limit {
                if steps >= limit {
                    // In WASM, avoid panicking if you prefer, but this is fine too.
                    panic!();
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

#[wasm_bindgen]
pub fn generate_seed() -> u32 {
    let prog = include_bytes!("../out.bin").to_vec();
    let prog = bincode::deserialize(&prog).unwrap();
    let mut m = Machine::new(16, prog);
    m.run();
    let crypto = window().unwrap().crypto().unwrap();
    let mut buf = [0u8; 4];
    crypto.get_random_values_with_u8_array(&mut buf).unwrap();
    u32::from_le_bytes(buf)
}
