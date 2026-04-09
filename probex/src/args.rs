use clap::{ArgGroup, Parser};

#[derive(Parser, Debug)]
#[command(name = "probex")]
#[command(about = "eBPF process tracing tool")]
#[command(version)]
#[command(group(
    ArgGroup::new("mode")
        .args(["view", "pid", "command"])
        .required(true)
))]
pub struct Args {
    /// Output parquet file (default: probex-YYYYMMDD-HHMMSS.parquet)
    #[arg(short, long)]
    pub output: Option<String>,

    /// Port for the viewer web interface
    #[arg(short, long, default_value = "8080")]
    pub port: u16,

    /// Don't launch the viewer after tracing
    #[arg(long, conflicts_with = "view")]
    pub no_viewer: bool,

    /// View an existing parquet trace file without tracing a new command
    #[arg(long, value_name = "PARQUET", conflicts_with_all = ["command", "pid"])]
    pub view: Option<String>,

    /// Attach to an existing process by PID instead of spawning a new command
    #[arg(long, value_name = "PID", conflicts_with_all = ["command", "view"])]
    pub pid: Option<u32>,

    /// Perf-style CPU clock sampling frequency (Hz)
    #[arg(long, value_name = "HZ", default_value_t = 1999)]
    pub sample_freq: u64,

    /// Tracing duration in seconds for --pid attach mode (default: 60)
    #[arg(long, value_name = "SECS", default_value_t = 60, requires = "pid")]
    pub attach_duration: u64,

    /// Command to run
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present_any = ["view", "pid"]
    )]
    pub command: Vec<String>,
}
