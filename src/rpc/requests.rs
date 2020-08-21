use serde::Deserialize;
use serde_json::json;

use crate::rpc::types::BlockHash;

pub struct GetBlockRequest {
    pub hash: BlockHash,
}

impl From<GetBlockRequest> for JsonRpcRequest {
    fn from(req: GetBlockRequest) -> JsonRpcRequest {
        JsonRpcRequest {
            method: "getblock",
            params: vec![req.hash.into(), 2.into()],
        }
    }
}

pub struct JsonRpcRequest {
    pub method: &'static str,
    pub params: Vec<serde_json::Value>,
}

impl Into<String> for JsonRpcRequest {
    fn into(self) -> String {
        json!({
            "jsonrpc": "1.0",
            "id": "rust-crypto",
            "method": self.method,
            "params": self.params,
        })
        .to_string()
    }
}

#[derive(Deserialize)]
pub struct JsonRpcResponse {
    pub result: Option<serde_json::Value>,
    pub error: Option<serde_json::Value>,
}

pub struct RequestBuilder {
    pub uri: String,
    pub auth: String,
}

impl RequestBuilder {
    pub fn build<T>(&self, msg: T) -> http::Request<JsonRpcRequest>
    where
        T: Into<JsonRpcRequest>,
    {
        http::Request::builder()
            .uri(&self.uri)
            .method(http::Method::POST)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::AUTHORIZATION, format!("Basic {}", &self.auth))
            .body(msg.into())
            .unwrap()
    }
}
