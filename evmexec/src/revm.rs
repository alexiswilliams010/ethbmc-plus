use revm::{
    database::{CacheDB, EmptyDB},
    primitives::{Address, Bytes, TxKind, U256},
    state::AccountInfo,
    bytecode::Bytecode,
    inspector::inspectors::TracerEip3155,
    Context,
    ExecuteCommitEvm,
    MainBuilder,
    MainContext,
};

use crate::genesis::Genesis;
use crate::evm::{EvmInput, ExecutionResult, State};
use crate::evmtrace::{ContextParser, InstructionContext};
use crate::ethereum_newtypes::Address as OldEvmAddress;
use crate::Error;
use std::io::{Write, BufRead};

#[derive(Debug, Clone, Copy)]
struct FlushWriter {
    writer: [u8; 1024],
    pos: usize,
}

impl FlushWriter {
    fn new() -> Self {
        Self { writer: [0; 1024], pos: 0 }
    }

    fn into_vec(self) -> Vec<u8> {
        self.writer[..self.pos].to_vec()
    }
}

impl Write for FlushWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let remaining = self.writer.len() - self.pos;
        let to_write = std::cmp::min(remaining, buf.len());
        self.writer[self.pos..self.pos + to_write].copy_from_slice(&buf[..to_write]);
        self.pos += to_write;
        Ok(to_write)
    }

    fn flush(&mut self) -> std::io::Result<()> {
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

    pub fn execute(self, input: EvmInput) -> Result<RevmResult, Error> {
        let input_clone = input.clone();
        let revm_input = Revm::evm_to_revm_input(input);
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
        let writer = FlushWriter::new();
        let mut evm = evm
            .with_inspector(TracerEip3155::new(Box::new(writer))
            .without_summary()
            .with_memory());

        // Execute the transaction and commit the changes back to the CacheDB
        let result = evm.replay_commit().unwrap();
        let trace = writer.into_vec();

        // Parse the trace into a Vec<InstructionContext>
        let instructions = Revm::parse_trace(trace, receiver);

        Ok(RevmResult {
            genesis: self.genesis,
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
            sender: Address::from_slice(&<[u8; 32]>::from(input.sender.0)), // Take last 20 bytes
            receiver: Address::from_slice(&<[u8; 32]>::from(input.receiver.0)), // Take last 20 bytes
            gas: input.gas,
            value: U256::from_be_bytes(<[u8; 32]>::from(input.value.0)),
        }
    }

    pub fn update_state_from_genesis(mut self, genesis: Genesis) -> Self {
        self.genesis = genesis;

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
            self.db.insert_account_info(Address::from_slice(&<[u8; 32]>::from(addr.0)), info);

            // For each storage slot, insert into the CacheDB
            for (slot, value) in acc_state.storage.iter() {
                let slot_u256 = U256::from_be_bytes(<[u8; 32]>::from(slot.0));
                let value_u256 = U256::from_be_bytes(<[u8; 32]>::from(value.0));
                self.db.insert_account_storage(Address::from_slice(&<[u8; 32]>::from(addr.0)), slot_u256, value_u256).unwrap();
            }
        }

        self
    }

    pub fn parse_trace(trace: Vec<u8>, receiver: OldEvmAddress) -> Vec<InstructionContext> {
        let mut buf = String::new();
        let mut instructions = Vec::new();
        let mut parser = ContextParser::new(receiver);
        let mut reader = std::io::Cursor::new(trace);

        while let Ok(d) = reader.read_line(&mut buf) {
            // end of stream
            if d == 0 {
                break;
            }
            if buf.contains("Fatal") {
                panic!("Could not fetch evm output: {}", buf);
            }

            // Attempts to detect the end of the trace by looking for the "root" keyword to indicate the start of the account object
            // Is this fragile? Yes, but until we switch over to revm this will work
            if buf.contains("root") {
                break;
            } else if let Some(ins) = parser.parse_trace_line(&buf) {
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
