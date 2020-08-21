use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub type BlockHash = String;
pub type TransactionHash = String;

#[derive(Deserialize, PartialEq, Debug)]
pub struct Block {
    pub hash: BlockHash,
    pub height: u64,
    pub tx: Vec<Transaction>,
    #[serde(rename = "nextblockhash")]
    pub next_block_hash: Option<BlockHash>,
}

#[derive(Deserialize, PartialEq, Debug)]
pub struct Transaction {
    pub hash: TransactionHash,
    pub vin: Vec<serde_json::Value>,
    pub vout: Vec<serde_json::Value>,
}

#[derive(Debug)]
pub enum Error {
    /// The requested resource could not be found
    NotFound,
    DeserializationError(serde_json::Error),
    HttpError(reqwest::Error),
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Error {
        Error::DeserializationError(err)
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::HttpError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_deserialization() {
        let data = r#"
            {
              "hash": "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
              "confirmations": 644581,
              "strippedsize": 215,
              "size": 215,
              "weight": 860,
              "height": 1,
              "version": 1,
              "versionHex": "00000001",
              "merkleroot": "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098",
              "tx": [
                "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"
              ],
              "time": 1231469665,
              "mediantime": 1231469665,
              "nonce": 2573394689,
              "bits": "1d00ffff",
              "difficulty": 1,
              "chainwork": "0000000000000000000000000000000000000000000000000000000200020002",
              "nTx": 1,
              "previousblockhash": "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
              "nextblockhash": "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"
            }
        "#;

        let block: Block = serde_json::from_str(&data).unwrap();

        assert_eq!(
            block,
            Block {
                height: 1,
                hash: String::from(
                    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
                ),
                tx: vec![String::from(
                    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858eeac00000000"
                )],
                next_block_hash: Some(String::from(
                    "000000006a625f06636b8bb6ac7b960a8d03705d1ace08b1a19da3fdcc99ddbd"
                )),
            }
        );
    }
}
