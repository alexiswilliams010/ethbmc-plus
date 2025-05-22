use clap::Parser;
use forge_runner::custom_tester::CustomTestArgs;

#[tokio::main]
async fn main() {
    let args = CustomTestArgs::parse();
    args.run().await.unwrap();
}