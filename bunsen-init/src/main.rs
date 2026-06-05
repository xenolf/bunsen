mod cmdline;
mod network;

pub const VSOCK_SPEC_PORT: u32 = 5000;
pub const VSOCK_STDOUT_PORT: u32 = 5001;
pub const VSOCK_STDERR_PORT: u32 = 5002;
pub const VSOCK_CONTROL_PORT: u32 = 5003;

#[cfg(target_os = "linux")]
mod init_linux;

fn main() {
    #[cfg(target_os = "linux")]
    init_linux::run();

    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("bunsen-init: Linux-only binary");
        std::process::exit(1);
    }
}
