extern crate evmexec;

#[macro_use]
extern crate maplit;

use std::str::FromStr;

use evmexec::{
    revm::{Revm, RevmInput},
    genesis::{Account, Genesis},
};

use revm::{primitives::{Address, Bytes, U256}, Database};

fn setup_evm() -> Revm {
    let mut genesis = Genesis::new();
    genesis.add_account(
        Address::from_str("0x0dfa72de72f96cf5b127b070e90d68ec9710797c").unwrap(),
        Account::new(U256::from(0), None, U256::from(1), None),
    );

    let code = hexdecode::decode("60806040526004361061004b5763ffffffff7c01000000000000000000000000000000000000000000000000000000006000350416637c52e3258114610050578063e9ca826c14610080575b600080fd5b34801561005c57600080fd5b5061007e73ffffffffffffffffffffffffffffffffffffffff60043516610095565b005b34801561008c57600080fd5b5061007e610145565b60005473ffffffffffffffffffffffffffffffffffffffff1633146100b657fe5b600154604080517f338ccd7800000000000000000000000000000000000000000000000000000000815273ffffffffffffffffffffffffffffffffffffffff84811660048301529151919092169163338ccd7891602480830192600092919082900301818387803b15801561012a57600080fd5b505af115801561013e573d6000803e3d6000fd5b5050505050565b6000805473ffffffffffffffffffffffffffffffffffffffff1916331790555600a165627a7a72305820b376cbf41ad45cba2c20890893f93f24efe850bf7eaf35fd12a0474576b4ac2d0029".as_bytes()).expect("Could not parse code array");
    genesis.add_account(
        Address::from_str("0x0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9").unwrap(),
        Account::new(
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
        Account::new(
            U256::from_str_radix("AABBCCDD", 16).unwrap(),
            Some(code.into()),
            U256::from(1),
            Some(hashmap!{
                U256::from(0) => U256::from_str_radix("0ad62f08b3b9f0ecc7251befbeff80c9bb488fe9", 16).unwrap(),
            }),
        ),
    );

    let mut evm = Revm::new(genesis);
    // Fold the genesis state into the CacheDB of the Revm instance
    evm.update_state_from_genesis();
    evm
}

#[test]
fn multiple_transactions_test() {
    // Setup the EVM from the genesis state
    let mut evm = setup_evm();
    let input = RevmInput {
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

    let input = RevmInput {
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
