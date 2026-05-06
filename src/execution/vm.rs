// =============================================================================
// src/execution/vm.rs — L2 Virtual Machine
// =============================================================================
//
// Bitcoin-native execution environment for L2 contracts.
// Implements EVM-like opcodes with Bitcoin Script verification.

use crate::{
    error::{BtcFiError, Result},
    types::{Address, U256},
    execution::state::{L2State, L2Transaction},
};

// ── VM Opcodes ────────────────────────────────────────────────────────────────

/// L2 opcodes, inspired by EVM but verifiable on Bitcoin.
#[derive(Debug, Clone, Copy)]
pub enum Opcode {
    // Arithmetic
    ADD,
    SUB,
    MUL,
    DIV,

    // Stack
    PUSH(U256),
    POP,

    // Storage
    SLOAD,
    SSTORE,

    // Control flow
    JUMP,
    JUMPI,
    RETURN,

    // Bitcoin-specific
    CHECKSIG,
    HASH256,
}

impl Opcode {
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Opcode::ADD),
            0x02 => Some(Opcode::SUB),
            0x03 => Some(Opcode::MUL),
            0x04 => Some(Opcode::DIV),
            0x50 => Some(Opcode::POP),
            0x51 => Some(Opcode::PUSH(U256::zero())), // Placeholder
            0x54 => Some(Opcode::SLOAD),
            0x55 => Some(Opcode::SSTORE),
            0x56 => Some(Opcode::JUMP),
            0x57 => Some(Opcode::JUMPI),
            0xF3 => Some(Opcode::RETURN),
            0xAC => Some(Opcode::CHECKSIG),
            0xA9 => Some(Opcode::HASH256),
            _ => None,
        }
    }
}

// ── VM Execution ──────────────────────────────────────────────────────────────

/// The L2 virtual machine.
#[derive(Debug)]
pub struct VM {
    /// Program counter.
    pc: usize,

    /// Stack.
    stack: Vec<U256>,

    /// Memory.
    memory: Vec<u8>,

    /// Call data.
    _calldata: Vec<u8>,

    /// Return data.
    returndata: Vec<u8>,
}

impl VM {
    pub fn new(calldata: Vec<u8>) -> Self {
        Self {
            pc: 0,
            stack: Vec::new(),
            memory: Vec::new(),
            _calldata: calldata,
            returndata: Vec::new(),
        }
    }

    /// Execute bytecode.
    pub fn execute(&mut self, bytecode: &[u8], state: &mut L2State) -> Result<()> {
        while self.pc < bytecode.len() {
            let opcode = bytecode[self.pc];
            self.pc += 1;

            match Opcode::from_u8(opcode) {
                Some(Opcode::ADD) => self.op_add()?,
                Some(Opcode::SUB) => self.op_sub()?,
                Some(Opcode::MUL) => self.op_mul()?,
                Some(Opcode::DIV) => self.op_div()?,
                Some(Opcode::POP) => self.op_pop()?,
                Some(Opcode::PUSH(val)) => self.op_push(val)?,
                Some(Opcode::SLOAD) => self.op_sload(state)?,
                Some(Opcode::SSTORE) => self.op_sstore(state)?,
                Some(Opcode::JUMP) => self.op_jump(bytecode)?,
                Some(Opcode::JUMPI) => self.op_jumpi(bytecode)?,
                Some(Opcode::RETURN) => return self.op_return(),
                Some(Opcode::CHECKSIG) => self.op_checksig()?,
                Some(Opcode::HASH256) => self.op_hash256()?,
                None => return Err(BtcFiError::VmInvalidOpcode { opcode }),
            }
        }
        Ok(())
    }

    fn op_add(&mut self) -> Result<()> {
        let a = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let b = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        self.stack.push(a + b);
        Ok(())
    }

    fn op_sub(&mut self) -> Result<()> {
        let a = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let b = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        self.stack.push(a - b);
        Ok(())
    }

    fn op_mul(&mut self) -> Result<()> {
        let a = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let b = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        self.stack.push(a * b);
        Ok(())
    }

    fn op_div(&mut self) -> Result<()> {
        let a = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let b = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        if b == U256::zero() {
            return Err(BtcFiError::VmDivisionByZero);
        }
        self.stack.push(a / b);
        Ok(())
    }

    fn op_pop(&mut self) -> Result<()> {
        self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        Ok(())
    }

    fn op_push(&mut self, val: U256) -> Result<()> {
        self.stack.push(val);
        Ok(())
    }

    fn op_sload(&mut self, state: &L2State) -> Result<()> {
        let slot = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let address = Address([0u8; 20]); // TODO: Get current contract address
        let value = state.trie.get(&address, &slot);
        self.stack.push(value);
        Ok(())
    }

    fn op_sstore(&mut self, state: &mut L2State) -> Result<()> {
        let slot = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let value = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let address = Address([0u8; 20]); // TODO: Get current contract address
        state.trie.set(&address, &slot, value);
        Ok(())
    }

    fn op_jump(&mut self, bytecode: &[u8]) -> Result<()> {
        let dest = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let dest_usize = dest.as_usize();
        if dest_usize >= bytecode.len() {
            return Err(BtcFiError::VmInvalidJumpDestination { dest: dest_usize });
        }
        self.pc = dest_usize;
        Ok(())
    }

    fn op_jumpi(&mut self, bytecode: &[u8]) -> Result<()> {
        let dest = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let cond = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        if cond != U256::zero() {
            let dest_usize = dest.as_usize();
            if dest_usize >= bytecode.len() {
                return Err(BtcFiError::VmInvalidJumpDestination { dest: dest_usize });
            }
            self.pc = dest_usize;
        }
        Ok(())
    }

    fn op_return(&mut self) -> Result<()> {
        let offset = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let size = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        let offset_usize = offset.as_usize();
        let size_usize = size.as_usize();
        if offset_usize + size_usize > self.memory.len() {
            return Err(BtcFiError::VmMemoryOutOfBounds);
        }
        self.returndata = self.memory[offset_usize..offset_usize + size_usize].to_vec();
        Ok(())
    }

    fn op_checksig(&mut self) -> Result<()> {
        // TODO: Implement Bitcoin-style signature check
        // Placeholder: always true
        self.stack.push(U256::one());
        Ok(())
    }

    fn op_hash256(&mut self) -> Result<()> {
        let input = self.stack.pop().ok_or(BtcFiError::VmStackUnderflow)?;
        // TODO: Hash the input
        self.stack.push(input); // Placeholder
        Ok(())
    }

    /// Get return data.
    pub fn returndata(&self) -> &[u8] {
        &self.returndata
    }
}

// ── Contract Execution ────────────────────────────────────────────────────────

/// Execute an L2 contract.
pub fn execute_contract(
    bytecode: &[u8],
    tx: &L2Transaction,
    state: &mut L2State,
) -> Result<Vec<u8>> {
    let mut vm = VM::new(tx.data.clone());
    vm.execute(bytecode, state)?;
    Ok(vm.returndata().to_vec())
}