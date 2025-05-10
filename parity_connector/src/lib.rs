extern crate futures;
extern crate serde;
#[macro_use]
extern crate serde_derive;
#[cfg_attr(test, macro_use)]
extern crate serde_json;

#[cfg(test)]
extern crate serde_test;

#[macro_use]
extern crate jsonrpc_client_core;
extern crate jsonrpc_client_http;

#[macro_use]
mod macros;
mod client;
mod types;

pub use types::{Block, BlockSelector};

use jsonrpc_client_http::{HttpHandle, HttpTransport};
use revm::primitives::{Address, U256};

use client::ParityClient;

/// Creates parity http client
pub fn create_client(ip: &str, port: isize) -> ParityConnector {
    ParityConnector::new(ip, port)
}

#[derive(Clone, Debug)]
pub struct ParityConnector {
    client: ParityClient<HttpHandle>,
}

impl ParityConnector {
    pub fn new(ip: &str, port: isize) -> Self {
        let transport = HttpTransport::new().standalone().unwrap();
        let transport_handle = transport
            .handle(&format!("http://{}:{}", ip, port))
            .unwrap();
        let client = ParityClient::new(transport_handle);
        ParityConnector { client }
    }

    pub fn blocknumber(&mut self) -> U256 {
        self.client.eth_blockNumber().call().unwrap()
    }

    pub fn block_by_number(&mut self, number: BlockSelector) -> Block {
        self.client
            .eth_getBlockByNumber(number, false)
            .call()
            .unwrap()
    }

    pub fn code(&mut self, addr: Address, block: BlockSelector) -> Vec<u8> {
        self.client
            .eth_getCode(addr, block)
            .call()
            .unwrap()
            .0
            .to_vec()
    }

    pub fn balance(&mut self, addr: Address, block: BlockSelector) -> U256 {
        self.client
            .eth_getBalance(addr, block)
            .call()
            .unwrap()
    }

    pub fn storage(&mut self, addr: Address, block: BlockSelector) -> Option<Vec<(U256, U256)>> {
        let stor = self.client.eth_getStorage(addr, block).call().ok()?;
        Some(
            stor.0
                .into_iter()
                .map(|v| v.into_iter())
                .map(|mut v| (v.next().unwrap(), v.next().unwrap()))
                .collect(),
        )
    }
}
