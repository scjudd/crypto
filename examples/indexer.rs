use crypto::rpc;

const GENESIS: &'static str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

fn main() {
    let client = rpc::BlockingClient::new(
        reqwest::blocking::Client::new(),
        rpc::RequestBuilder {
            uri: String::from("http://localhost:8332/"),
            auth: String::from("c3BlbmNlcjpodW50ZXIy"), // spencer:hunter2
        },
    );

    let mut block = client
        .get_block(String::from(GENESIS))
        .expect("genesis block not found on-chain");

    loop {
        println!("processing block {}: {}", block.height, block.hash);

        println!("transactions: {:#?}", block.tx);

        block = client
            .get_block(block.next_block_hash.unwrap())
            .expect("block does not exist on-chain");
    }
}
