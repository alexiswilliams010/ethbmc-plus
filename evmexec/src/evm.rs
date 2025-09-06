use log::info;
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

// For providing counterexamples in Foundry
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct ForgeInput {
    pub input_data: String,
    pub sender: String,
    pub receiver: String,
}

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

pub struct Evm {
    pub db: CacheDB<EmptyDB>,
    // We don't really need to use a Genesis but will use it to update the CacheDB for now
    // TODO: Eventually the the symbolic analysis will be migrated to all Revm types
    pub genesis: Genesis,
}

#[derive(Debug, Clone)]
pub struct EvmInput {
    pub input_data: Bytes,
    pub sender: Address,
    pub receiver: Address,
    pub gas: u32,
    pub value: U256,
}

impl Evm {
    pub fn new(genesis: Genesis) -> Self {
        Self {
            db: CacheDB::new(EmptyDB::default()),
            genesis: genesis,
        }
    }

    pub fn execute(&mut self, input: EvmInput) -> Result<EvmResult, Error> {
        // Peek into the nonce of the sender from the loaded CacheDB so it can be added to the tx
        let nonce = self.db.load_account(input.sender).map_or(0, |acc| acc.info.nonce);

        // Create a new writer to capture the trace of the execution
        let mut writer = FlushWriter::new();

        // Setup the EVM from the stored CacheDB and modify the transaction to include the input data
        let mut evm = Context::mainnet()
            .with_db(&mut self.db)
            .modify_tx_chained(|tx| {
                tx.caller = input.sender;
                tx.kind = TxKind::Call(input.receiver);
                tx.data = input.input_data.clone();
                tx.value = input.value;
                tx.gas_limit = input.gas as u64;
                tx.nonce = nonce;
            })
            .build_mainnet()
            // Set an inspector to capture the trace of the execution
            .with_inspector(TracerEip3155::new(Box::new(writer.clone()))
            .without_summary()
            .with_memory());

        // Execute the transaction and commit the changes back to the CacheDB
        let result = evm.inspect_replay_commit().unwrap();
        info!("result: {:?}", result);
        let trace = writer.get_buffer();

        // Parse the trace into a Vec<InstructionContext>
        let instructions = Evm::parse_trace(trace, input.receiver);

        Ok(EvmResult {
            genesis: self.genesis.clone(),
            input: input,
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

pub struct EvmResult {
    pub genesis: Genesis,
    pub input: EvmInput,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use maplit::hashmap;
    use revm::Database;
    use crate::genesis::{Genesis, Account as GenesisAccount};

    fn setup_evm() -> Evm {
        let mut genesis = Genesis::new();
        genesis.add_account(
            Address::from_str("0x0dfa72de72f96cf5b127b070e90d68ec9710797c").unwrap(),
            GenesisAccount::new(U256::from(0), None, U256::from(1), None),
        );

        let code = hexdecode::decode("60806040526004361061004b5763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416637c52e3258114610050578063e9ca826c14610080575b600080fd5b34801561005c57600080fd5b5061007e73ffffffffffffffffffffffffffffffffffffffff60043516610095565b005b34801561008c57600080fd5b5061007e610145565b60005473ffffffffffffffffffffffffffffffffffffffff1633146100b657fe5b600154604080517f338ccd7800000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff84811660048301529151919092169163338ccd7891602480830192600092919082900301818387803b15801561012a57600080fd5b505af115801561013e573d6000803e3d6000fd5b5050505050565b6000805473ffffffffffffffffffffffffffffffffffffffff1916331790555600a165627a7a72305820b376cbf41ad45cba2c20890893f93f24efe850bf7eaf35fd12a0474576b4ac2d0029".as_bytes()).expect("Could not parse code array");
        genesis.add_account(
            Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap(),
            GenesisAccount::new(
                U256::from(0),
                Some(code.into()),
                U256::from(1),
                Some(hashmap!{
                    U256::from(0) => U256::from(0),
                    U256::from(1) => U256::from_str_radix("06c249452ee469d839942e05b8492dbb9f9c70ac", 16).unwrap(),
                }),
            ),
        );

        let code = hexdecode::decode("0x606060405260043610603e5763ffffffff7c0100000000000000000000000000000000000000000000000000000000600035041663338ccd7881146043575b600080fd5b3415604d57600080fd5b606c73ffffffffffffffffffffffffffffffffffffffff60043516606e565b005b6000543373ffffffffffffffffffffffffffffffffffffffff908116911614609257fe5b8073ffffffffffffffffffffffffffffffffffffffff166108fc3073ffffffffffffffffffffffffffffffffffffffff16319081150290604051600060405180830381858888f19350505050151560e857600080fd5b505600a165627a7a72305820d94e263975863b2024dc4bfaba0287941709bc576381ae567f9683d8fc2052940029".as_bytes()).expect("Could not parse code array");
        genesis.add_account(
            Address::from_str("0x06c249452ee469d839942e05b8492dbb9f9c70ac").unwrap(),
            GenesisAccount::new(
                U256::from_str_radix("AABBCCDD", 16).unwrap(),
                Some(code.into()),
                U256::from(1),
                Some(hashmap!{
                    U256::from(0) => U256::from_str_radix("0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9", 16).unwrap(),
                }),
            ),
        );

        let mut evm = Evm::new(genesis);
        // Fold the genesis state into the CacheDB of the Evm instance
        evm.update_state_from_genesis();
        evm
    }

    #[test]
    fn multiple_transactions_test() {
        // Setup the EVM from the genesis state
        let mut evm = setup_evm();
        let input = EvmInput {
            value: U256::from(0),
            input_data: Bytes::from_str("e9ca826c000000800001020800000000000000008000000000000000000000001000000000000000000000000000000000000010101010101010100010110001000000000100000001012001010101010208010480082000401800120001080402080082040802001402080408080002004040210011010208202020084001020201040220042000041040000280800202808001018001").expect("Could not parse input"),
            sender: Address::from_str("0x0dfa72de72f96cf5b127b070e90d68ec9710797c").unwrap(),
            receiver: Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap(),
            gas: 100_000,
        };
        evm.execute(input).expect("Could not update evm");

        // check storage overwritten
        assert_eq!(
            evm.db.storage(Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap(), U256::from(0)).unwrap(),
            U256::from_str_radix("dfa72de72f96cf5b127b070e90d68ec9710797c", 16).unwrap()
        );

        // check values not changed
        assert_eq!(
            evm.db.load_account(Address::from_str("0x0dfa72de72f96cf5b127b070e90d68ec9710797c").unwrap()).unwrap().info.balance,
            U256::from(0),
        );
        assert_eq!(
            evm.db.load_account(Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap()).unwrap().info.balance,
            U256::from(0),
        );
        assert_eq!(
            evm.db.load_account(Address::from_str("0x06c249452ee469d839942e05b8492dbb9f9c70ac").unwrap()).unwrap().info.balance,
            U256::from_str_radix("AABBCCDD", 16).unwrap(),
        );

        // check nonces updated
        assert_eq!(
            evm.db.load_account(Address::from_str("0x0dfa72de72f96cf5b127b070e90d68ec9710797c").unwrap()).unwrap().info.nonce,
            2u64,
        );
        assert_eq!(
            evm.db.load_account(Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap()).unwrap().info.nonce,
            1u64,
        );
        assert_eq!(
            evm.db.load_account(Address::from_str("0x06c249452ee469d839942e05b8492dbb9f9c70ac").unwrap()).unwrap().info.nonce,
            1u64,
        );

        let input = EvmInput {
            value: U256::from(0),
            input_data: Bytes::from_str("7c52e3250000000000081000000002000dfa72de72f96cf5b127b070e90d68ec9710797c00000000000000000000000000000000000008000100040008018008204001014010020410080202010408010201010180010101200101010201010240401802040010101010000001008000000000001000000018040000202000010000000001000000").expect("Could not parse input"),
            sender: Address::from_str("0x0dfa72de72f96cf5b127b070e90d68ec9710797c").unwrap(),
            receiver: Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap(),
            gas: 100_000,
        };
        evm.execute(input).expect("Could not update evm");

        // check values
        assert_eq!(
            evm.db.load_account(Address::from_str("0x0dfa72de72f96cf5b127b070e90d68ec9710797c").unwrap()).unwrap().info.balance,
            U256::from_str_radix("AABBCCDD", 16).unwrap(),
        );
        assert_eq!(
            evm.db.load_account(Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap()).unwrap().info.balance,
            U256::from(0),
        );
        assert_eq!(
            evm.db.load_account(Address::from_str("0x06c249452ee469d839942e05b8492dbb9f9c70ac").unwrap()).unwrap().info.balance,
            U256::from(0),
        );

        // check nonces updated
        assert_eq!(
            evm.db.load_account(Address::from_str("0x0dfa72de72f96cf5b127b070e90d68ec9710797c").unwrap()).unwrap().info.nonce,
            3u64,
        );
        assert_eq!(
            evm.db.load_account(Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap()).unwrap().info.nonce,
            1u64,
        );
        assert_eq!(
            evm.db.load_account(Address::from_str("0x06c249452ee469d839942e05b8492dbb9f9c70ac").unwrap()).unwrap().info.nonce,
            1u64,
        );
    }
}
