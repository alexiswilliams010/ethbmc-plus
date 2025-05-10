use revm::{
    bytecode::Bytecode, database::{CacheDB, EmptyDB},
    inspector::inspectors::TracerEip3155,
    primitives::{Address, Bytes, TxKind, U256, HashMap},
    state::{Account, AccountInfo},
    Context,
    InspectCommitEvm,
    MainBuilder,
    MainContext,
};

use crate::genesis::Genesis;
use crate::evmtrace::{ContextParser, InstructionContext};
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

#[derive(Debug, Clone)]
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

    pub fn execute(&mut self, input: RevmInput) -> Result<RevmResult, Error> {
        let input_clone = input.clone();

        // Setup the EVM from the stored CacheDB and modify the transaction to include the input data
        let evm = Context::mainnet()
            .with_db(self.db.clone())
            .modify_tx_chained(|tx| {
                tx.caller = input.sender;
                tx.kind = TxKind::Call(input.receiver);
                tx.data = input.input_data.clone();
                tx.value = input.value;
                tx.gas_limit = input.gas as u64;
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
        let instructions = Revm::parse_trace(trace, input.receiver);

        Ok(RevmResult {
            genesis: self.genesis.clone(),
            input: input_clone,
            result: ExecutionResult {
                trace: instructions,
                new_state: State::default(),
            },
        })
    }

    pub fn update_state_from_genesis(&mut self) {
        // Update the CacheDB using the AccountInfo in the provided genesis
        for (addr, acc_state) in self.genesis.alloc.iter() {
            let mut info = AccountInfo::default();

            // Set code if not empty
            if !acc_state.code.is_empty() {
                info = info.with_code(Bytecode::new_raw(acc_state.code.clone()));
            }

            // Convert balance from WU256 to U256
            info = info.with_balance(acc_state.balance);

            // Convert nonce from WU256 to u64
            info = info.with_nonce(acc_state.nonce.try_into().unwrap());

            // Convert address and insert the AccountInfo into the CacheDB
            self.db.insert_account_info(*addr, info);

            // For each storage slot, insert into the CacheDB
            for (slot, value) in acc_state.storage.iter() {
                self.db.insert_account_storage(*addr, *slot, *value).unwrap();
            }
        }
    }

    pub fn parse_trace(trace: String, receiver: Address) -> Vec<InstructionContext> {
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

            if let Some(ins) = parser.parse_trace_line(&buf) {
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
    pub input: RevmInput,
    pub result: ExecutionResult,
}

pub struct ExecutionResult {
    pub trace: Vec<InstructionContext>,
    pub new_state: State,
}

#[derive(Debug, Clone, Default)]
pub struct State {
    pub accounts: HashMap<Address, Account>,
}
