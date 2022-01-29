use std::path::PathBuf;

#[derive(clap::Parser)]
#[clap(setting(clap::AppSettings::TrailingVarArg))]
pub struct Args {
    pub binary_to_trace: PathBuf,
    #[clap(short = 'l')]
    pub library_functions_to_trace: Vec<String>,
    #[clap(long = "all-library-functions")]
    pub trace_all_library_functions: bool,
    #[clap(short = 's')]
    pub syscalls_to_trace: Vec<String>,
    #[clap(long = "all-syscalls")]
    pub trace_all_syscalls: bool,
    pub tracee_args: Vec<String>,
}

/// Expresses the users request to trace a given trace-able thing.
pub enum TraceRequest {
    All,
    /// Names of the syscall/function the user would like to trace.
    ///
    /// This can be empty, in which case we will not trace any of this thing.
    These(Vec<String>),
    NoSpecificRequest,
}

impl Args {
    pub fn syscall_trace_request(&self) -> TraceRequest {
        if self.trace_all_syscalls {
            TraceRequest::All
        } else if !self.syscalls_to_trace.is_empty() {
            TraceRequest::These(self.syscalls_to_trace.clone())
        } else {
            TraceRequest::NoSpecificRequest
        }
    }
    pub fn library_function_trace_request(&self) -> TraceRequest {
        if self.trace_all_library_functions {
            TraceRequest::All
        } else if !self.library_functions_to_trace.is_empty() {
            TraceRequest::These(self.library_functions_to_trace.clone())
        } else {
            TraceRequest::NoSpecificRequest
        }
    }
}
