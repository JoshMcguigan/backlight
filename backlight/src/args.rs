use std::path::PathBuf;

#[derive(clap::Parser)]
pub struct Args {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand)]
pub enum Command {
    Trace {
        binary_to_trace: PathBuf,
        #[clap(short = 'l')]
        library_function_to_trace: String,
    },
}