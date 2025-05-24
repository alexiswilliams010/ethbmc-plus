use clap::Parser;
use forge_runner::custom_tester::CustomTestArgs;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = CustomTestArgs::parse();
    if let Err(e) = args.run().await {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}