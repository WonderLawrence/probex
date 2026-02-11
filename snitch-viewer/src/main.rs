//! Snitch Trace Viewer
//!
//! A web-based visualization tool for snitch parquet trace files.
//! Uses Dioxus fullstack with DataFusion for efficient querying.

#[cfg(any(feature = "server", feature = "web"))]
mod app;
#[cfg(any(feature = "server", feature = "web"))]
mod server;

#[cfg(feature = "server")]
mod cli {
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(name = "snitch-viewer")]
    #[command(about = "Web-based visualization for snitch trace files")]
    #[command(version)]
    pub struct Args {
        /// Parquet trace file to visualize (or set SNITCH_FILE env var)
        #[arg(short, long, env = "SNITCH_FILE", default_value = "trace.parquet")]
        pub file: String,

        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        pub port: u16,

        /// Address to bind to
        #[arg(short, long, default_value = "0.0.0.0")]
        pub address: String,
    }
}

#[cfg(feature = "server")]
#[tokio::main]
async fn main() {
    if let Err(error) = run_server().await {
        eprintln!("Failed to start snitch-viewer: {error}");
        std::process::exit(1);
    }
}

#[cfg(feature = "server")]
async fn run_server() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use clap::Parser;
    use dioxus::prelude::{DioxusRouterExt, ServeConfig};
    use std::io::{Error as IoError, ErrorKind};

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = cli::Args::parse();
    let parquet_path = std::path::PathBuf::from(&args.file);

    server::initialize(parquet_path).await?;

    let bind_addr = format!("{}:{}", args.address, args.port);
    log::info!("snitch-viewer available at http://{bind_addr}");

    let public_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("public")))
        .ok_or_else(|| IoError::other("Failed to locate executable directory"))?;
    if !public_dir.is_dir() {
        return Err(IoError::new(
            ErrorKind::NotFound,
            format!(
                "Missing Dioxus public assets at {}. Use `dx serve -p snitch-viewer` for \
development or `dx bundle --platform server --fullstack -p snitch-viewer` for distributable builds.",
                public_dir.display()
            ),
        )
        .into());
    }

    let router = dioxus::server::axum::Router::new()
        .serve_dioxus_application(ServeConfig::new(), app::App)
        .into_make_service();

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    dioxus::server::axum::serve(listener, router).await?;

    Ok(())
}

#[cfg(all(not(feature = "server"), feature = "web"))]
fn main() {
    dioxus::launch(app::App);
}

#[cfg(all(not(feature = "server"), not(feature = "web")))]
fn main() {
    eprintln!(
        "snitch-viewer requires a platform feature. Use `--features server` (backend) or \
`--features web` (wasm)."
    );
    std::process::exit(1);
}
