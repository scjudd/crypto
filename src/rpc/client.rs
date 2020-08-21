use crate::rpc::requests::*;
use crate::rpc::types::{Block, BlockHash, Error, Transaction};

use std::convert::TryInto;

pub struct BlockingClient<E> {
    executer: E,
    builder: RequestBuilder,
}

impl<E: BlockingExecute> BlockingClient<E> {
    pub fn new(executer: E, builder: RequestBuilder) -> BlockingClient<E> {
        BlockingClient { executer, builder }
    }

    pub fn get_block(&self, hash: BlockHash) -> Result<Block, Error> {
        let response = self.execute(GetBlockRequest { hash })?;
        let block = serde_json::from_value(response.result.unwrap())?;
        Ok(block)
    }

    #[inline]
    fn execute<T>(&self, request: T) -> Result<JsonRpcResponse, Error>
    where
        T: Into<JsonRpcRequest>,
    {
        Ok(self.executer.execute(self.builder.build(request))?)
    }
}

pub trait BlockingExecute {
    fn execute(&self, request: http::Request<JsonRpcRequest>) -> Result<JsonRpcResponse, Error>;
}

//#[cfg(feature = "reqwest")]
impl BlockingExecute for reqwest::blocking::Client {
    fn execute(&self, request: http::Request<JsonRpcRequest>) -> Result<JsonRpcResponse, Error> {
        let response = self.execute(request.try_into().expect("invalid http request"))?;
        Ok(response.json()?)
    }
}

impl Into<reqwest::blocking::Body> for JsonRpcRequest {
    fn into(self) -> reqwest::blocking::Body {
        let string: String = self.into();
        string.into()
    }
}
