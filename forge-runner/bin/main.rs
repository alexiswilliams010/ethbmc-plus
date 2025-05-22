use clap::Parser;
use forge_runner::custom_tester::CustomTestArgs;

#[tokio::main]
async fn main() {
    let args = CustomTestArgs::parse();
    if let Err(e) = args.run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}