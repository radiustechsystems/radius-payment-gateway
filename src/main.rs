use clap::Parser;
use radius_gateway::pages::Pages;
use radius_gateway::server::shutdown_signal;
use radius_gateway::{App, Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = Config::parse();
    if let Some(dir) = &config.export_pages {
        let written = Pages::export(dir)?;
        println!("wrote {written} files to {}", dir.display());
        return Ok(());
    }
    radius_gateway::telemetry::init(&config)?;
    let app = App::bind(&config).await?;
    app.serve(shutdown_signal()).await
}
