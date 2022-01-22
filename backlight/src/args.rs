use std::path::PathBuf;

#[derive(clap::Parser)]
#[clap(setting(clap::AppSettings::TrailingVarArg))]
pub struct Args {
    pub binary_to_trace: PathBuf,
    #[clap(short = 'l')]
    pub library_functions_to_trace: Vec<String>,
    #[clap(short = 's')]
    pub syscalls_to_trace: Vec<String>,
    pub tracee_args: Vec<String>,
}
