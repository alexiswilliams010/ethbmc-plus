use revm::{
    bytecode::Bytecode, database::{CacheDB, EmptyDB},
    inspector::inspectors::TracerEip3155,
    primitives::{Address, Bytes, TxKind, U256},
    state::AccountInfo,
    Context,
    InspectCommitEvm,
    MainBuilder,
    MainContext,
};

use crate::genesis::Genesis;
use crate::evm::{EvmInput, ExecutionResult, State};
use crate::evmtrace::{ContextParser, InstructionContext};
use crate::ethereum_newtypes::Address as OldEvmAddress;
use crate::Error;
use std::io::{Write, BufRead};
use std::cell::RefCell;
use std::rc::Rc;

#[derive(Debug, Clone)]
struct FlushWriter {
    buffer: Rc<RefCell<Vec<u8>>>,
    flushed: Rc<RefCell<bool>>,
}

impl FlushWriter {
    fn new() -> Self {
        Self { 
            buffer: Rc::new(RefCell::new(Vec::new())),
            flushed: Rc::new(RefCell::new(false)),
        }
    }

    fn get_buffer(&mut self) -> String {
        // Ensure data is flushed before returning
        self.flush().unwrap();
        String::from_utf8_lossy(&self.buffer.borrow()).to_string()
    }
}

impl Write for FlushWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.borrow_mut().extend_from_slice(buf);
        *self.flushed.borrow_mut() = false;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !*self.flushed.borrow() {
            // Here we could do additional processing if needed
            // For now, we just mark as flushed
            *self.flushed.borrow_mut() = true;
        }
        Ok(())
    }
}

pub struct Revm {
    pub db: CacheDB<EmptyDB>,
    // We don't need really need to use a Genesis but will use it to update the CacheDB for now
    // TODO: Eventually the the symbolic analysis will be migrated to all Revm types
    pub genesis: Genesis,
}

#[derive(Debug)]
pub struct RevmInput {
    pub input_data: Bytes,
    pub sender: Address,
    pub receiver: Address,
    pub gas: u32,
    pub value: U256,
}

impl Revm {
    pub fn new(genesis: Genesis) -> Self {
        Self {
            db: CacheDB::new(EmptyDB::default()),
            genesis: genesis,
        }
    }

    pub fn execute(&mut self, input: EvmInput) -> Result<RevmResult, Error> {
        let input_clone = input.clone();
        let revm_input = Revm::evm_to_revm_input(input);
        println!("revm_input: {:?}", revm_input);
        let receiver = input_clone.receiver.clone();
        // Setup the EVM from the stored CacheDB and modify the transaction to include the input data
        let evm = Context::mainnet()
            .with_db(self.db.clone())
            .modify_tx_chained(|tx| {
                tx.caller = revm_input.sender;
                tx.kind = TxKind::Call(revm_input.receiver);
                tx.data = revm_input.input_data.clone();
                tx.value = revm_input.value;
                tx.gas_limit = revm_input.gas as u64;
            })
            .build_mainnet();

        // Set an inspector to capture the trace of the execution
        let mut writer = FlushWriter::new();
        let mut evm = evm
            .with_inspector(TracerEip3155::new(Box::new(writer.clone()))
            .without_summary()
            .with_memory());

        // Execute the transaction and commit the changes back to the CacheDB
        let result = evm.inspect_replay_commit().unwrap();
        println!("result: {:?}", result);
        let trace = writer.get_buffer();

        // Parse the trace into a Vec<InstructionContext>
        let instructions = Revm::parse_trace(trace, receiver);

        Ok(RevmResult {
            genesis: self.genesis.clone(),
            input: input_clone,
            result: ExecutionResult {
                trace: instructions,
                new_state: State::default(),
            },
        })
    }

    pub fn evm_to_revm_input(input: EvmInput) -> RevmInput {
        RevmInput {
            input_data: Bytes::from(input.input_data.0.clone()),
            sender: Address::from_slice(&<[u8; 32]>::from(input.sender.0)[12..]), // Take last 20 bytes
            receiver: Address::from_slice(&<[u8; 32]>::from(input.receiver.0)[12..]), // Take last 20 bytes
            gas: input.gas,
            value: U256::from_be_bytes(<[u8; 32]>::from(input.value.0)),
        }
    }

    pub fn update_state_from_genesis(&mut self) {
        // Update the CacheDB using the AccountInfo in the provided genesis
        for (addr, acc_state) in self.genesis.alloc.iter() {
            let mut info = AccountInfo::default();

            // Set code if not empty
            if !acc_state.code.is_empty() {
                let bytes = Bytecode::new_raw(Bytes::from(acc_state.code.0.clone()));
                info = info.with_code(bytes);
            }

            // Convert balance from WU256 to U256
            info = info.with_balance(U256::from_be_bytes(<[u8; 32]>::from(acc_state.balance.0)));

            // Convert nonce from WU256 to u64
            info = info.with_nonce(acc_state.nonce.0.as_u64());

            // Convert address and insert the AccountInfo into the CacheDB
            self.db.insert_account_info(Address::from_slice(&<[u8; 32]>::from(addr.0)[12..]), info);

            // For each storage slot, insert into the CacheDB
            for (slot, value) in acc_state.storage.iter() {
                let slot_u256 = U256::from_be_bytes(<[u8; 32]>::from(slot.0));
                let value_u256 = U256::from_be_bytes(<[u8; 32]>::from(value.0));
                self.db.insert_account_storage(Address::from_slice(&<[u8; 32]>::from(addr.0)[12..]), slot_u256, value_u256).unwrap();
            }
        }
    }

    pub fn parse_trace(trace: String, receiver: OldEvmAddress) -> Vec<InstructionContext> {
        let mut buf = String::new();
        let mut instructions = Vec::new();
        let mut parser = ContextParser::new(receiver);
        let mut reader = std::io::Cursor::new(trace);

        while let Ok(d) = reader.read_line(&mut buf) {
            println!("buf: {}", buf);
            // end of stream
            if d == 0 {
                break;
            }
            if buf.contains("Fatal") {
                panic!("Could not fetch evm output: {}", buf);
            }

            if let Some(ins) = parser.parse_trace_line(&buf) {
                println!("ins: {:?}", ins);
                instructions.push(ins);
            }

            // clear buffer for reuse
            buf.clear();
        }

        instructions
    }
}

pub struct RevmResult {
    pub genesis: Genesis,
    pub input: EvmInput,
    pub result: ExecutionResult,
}
