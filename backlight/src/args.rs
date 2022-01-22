use std::path::PathBuf;

#[derive(clap::Parser)]
pub struct Args {
    pub binary_to_trace: PathBuf,
    #[clap(short = 'l')]
    pub library_functions_to_trace: Vec<String>,
    #[clap(short = 's')]
    pub syscalls_to_trace: Vec<String>,
}
