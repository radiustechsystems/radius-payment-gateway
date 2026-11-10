use clap::Parser;
use radius_gateway::server::shutdown_signal;
use radius_gateway::{App, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    radius_gateway::telemetry::init(&config)?;
    let app = App::bind(&config).await?;
    app.serve(shutdown_signal()).await
}
