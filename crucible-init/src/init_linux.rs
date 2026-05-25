//! PID-1 guest init implementation (Linux only).
//!
//! Boot sequence:
//!   1. Mount /proc /sys /dev /tmp
//!   2. Read spec from kernel cmdline (crucible_spec=<base64-json>)
//!   3. Mount /dev/vdb (workspace ext4) at /workspace
//!   4. Connect stdout/stderr vsock sockets to the host (ports 5001 / 5002)
//!   5. Listen on vsock port 5003; accept one control connection from the host
//!   6. Fork + exec the agent with stdin=/dev/null, stdout/stderr=pipes
//!   7. Relay agent stdout/stderr to vsock; relay control commands as signals
//!   8. Reap all zombies; exit when the agent exits

use libc::{
    AF_VSOCK, SOCK_STREAM, SIGTERM, SIGKILL, SIGSTOP, SIGCONT,
    c_void, pid_t,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::mem;
use std::os::unix::io::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crate::network::GuestNetwork;

/// Toggled on at startup if the kernel cmdline contains `crucible_init_debug=1`.
/// When false, [`dbg`] is a no-op.
static DEBUG_ENABLED: AtomicBool = AtomicBool::new(false);

/// Append a line to /workspace/init.log AND echo to stderr (kernel console).
/// /workspace is extracted back to the host after the VM exits, so these
/// lines are visible there even though the FC run_dir is wiped. fsync each
/// line so writes survive the kernel-panic-on-PID1-exit reboot path.
///
/// No-op unless [`DEBUG_ENABLED`] is set — gated to avoid leaking diagnostics
/// (and a per-run `init.log`) into normal runs.
fn dbg(msg: &str) {
    if !DEBUG_ENABLED.load(Ordering::Relaxed) {
        return;
    }
    eprintln!("[init] {msg}");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/workspace/init.log")
    {
        let _ = writeln!(f, "{msg}");
        let _ = f.sync_all();
    }
}

const VMADDR_CID_HOST: u32 = 2;
const VMADDR_CID_ANY: u32 = u32::MAX;

#[repr(C)]
struct SockaddrVm {
    svm_family: u16,
    svm_reserved1: u16,
    svm_port: u32,
    svm_cid: u32,
    svm_zero: [u8; 4],
}

#[derive(Deserialize)]
struct InitSpec {
    cmd: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default = "default_grace")]
    stop_grace_seconds: u64,
    /// Per-Run network for `eth0`. Absent on host-supervisor Runs that don't
    /// configure a TAP (e.g. the smoke test).
    #[serde(default)]
    network: Option<GuestNetwork>,
}

fn default_grace() -> u64 { 10 }

pub fn run() -> ! {
    mount_filesystems();

    let cmdline = std::fs::read_to_string("/proc/cmdline")
        .expect("cannot read /proc/cmdline");
    if crate::cmdline::debug_enabled(&cmdline) {
        DEBUG_ENABLED.store(true, Ordering::Relaxed);
    }
    let spec_json = crate::cmdline::extract_spec(&cmdline)
        .expect("crucible_spec not found in kernel cmdline");
    let spec: InitSpec = serde_json::from_str(&spec_json)
        .expect("invalid spec JSON");

    mount_workspace();

    // Bring up eth0 if the host configured a per-Run network. Failure is
    // logged but not fatal: the L7 proxy address injected as HTTPS_PROXY
    // will simply be unreachable, and the agent will see a connection
    // error. The L3 enforcement layer that makes the network load-bearing
    // is a follow-up slice.
    if let Some(net) = spec.network.as_ref() {
        dbg(&format!(
            "configuring eth0: guest={} host={} prefix={}",
            net.guest_ip, net.host_ip, net.prefix_len
        ));
        if let Err(e) = crate::network::configure_eth0(net) {
            eprintln!("crucible-init: configure_eth0 failed: {e}");
            dbg(&format!("configure_eth0 failed: {e}"));
        }
        // Point libc resolvers at the host-side DNS listener. Agents that
        // honour HTTPS_PROXY don't need this (the proxy resolves names
        // server-side), but agents that probe DNS directly do. Failure is
        // logged but not fatal: the bind mount can fail when the rootfs
        // image lacks /etc/resolv.conf (rare) or when it's a symlink, in
        // which case the agent still has HTTPS_PROXY as the fallback.
        if let Err(e) = crate::network::install_resolv_conf(net) {
            eprintln!("crucible-init: install_resolv_conf failed: {e}");
            dbg(&format!("install_resolv_conf failed: {e}"));
        } else {
            dbg(&format!("installed resolv.conf -> {}", net.host_ip));
        }
    }

    // Connect stdout/stderr before forking so sockets are ready.
    let stdout_vsock = vsock_connect(VMADDR_CID_HOST, crate::VSOCK_STDOUT_PORT)
        .expect("cannot connect stdout vsock");
    let stderr_vsock = vsock_connect(VMADDR_CID_HOST, crate::VSOCK_STDERR_PORT)
        .expect("cannot connect stderr vsock");

    // Listen on control port; the host connects after starting the VM.
    let control_vsock = vsock_accept(crate::VSOCK_CONTROL_PORT)
        .expect("cannot accept control vsock");

    dbg(&format!("spec.cmd = {:?}", spec.cmd));
    dbg(&format!(
        "spec.env keys = {:?}",
        spec.env.keys().collect::<Vec<_>>()
    ));

    let (child_pid, stdout_r, stderr_r) = fork_exec(&spec);
    let pgid = child_pid;
    dbg(&format!("forked agent pid={child_pid}"));

    let stdout_bytes = Arc::new(AtomicU64::new(0));
    let stderr_bytes = Arc::new(AtomicU64::new(0));

    // I/O relay threads — save handles so we can join before exit.
    let stdout_thread = {
        let mut sw = unsafe { std::fs::File::from_raw_fd(stdout_vsock) };
        let counter = stdout_bytes.clone();
        std::thread::spawn(move || {
            let mut r = unsafe { std::fs::File::from_raw_fd(stdout_r) };
            let n = io::copy(&mut r, &mut sw).unwrap_or(0);
            counter.store(n, Ordering::SeqCst);
        })
    };
    let stderr_thread = {
        let mut sw = unsafe { std::fs::File::from_raw_fd(stderr_vsock) };
        let counter = stderr_bytes.clone();
        std::thread::spawn(move || {
            let mut r = unsafe { std::fs::File::from_raw_fd(stderr_r) };
            let n = io::copy(&mut r, &mut sw).unwrap_or(0);
            counter.store(n, Ordering::SeqCst);
        })
    };

    // Control relay thread.
    let grace = spec.stop_grace_seconds;
    std::thread::spawn(move || {
        control_loop(control_vsock, pgid, grace);
    });

    // Main thread: reap all zombies; stop when our direct child exits.
    let (exit_code, signal) = wait_for_agent(child_pid);
    dbg(&format!(
        "agent exited code={exit_code} signal={signal}"
    ));
    // Drain relay threads before exit so all buffered output reaches the host.
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
    dbg(&format!(
        "relay finished stdout_bytes={} stderr_bytes={}",
        stdout_bytes.load(Ordering::SeqCst),
        stderr_bytes.load(Ordering::SeqCst),
    ));
    // Flush all dirty pages (notably /workspace/init.log on the ext4) before
    // exit, otherwise the kernel-panic-on-PID1-exit reboot will lose them.
    unsafe { libc::sync(); }
    unsafe { libc::exit(exit_code) };
}

// ─── Filesystem mounts ─────────────────────────────────────────────────────

fn mount_filesystems() {
    let _ = std::fs::create_dir_all("/proc");
    let _ = std::fs::create_dir_all("/sys");
    let _ = std::fs::create_dir_all("/tmp");
    let _ = std::fs::create_dir_all("/dev");
    let _ = std::fs::create_dir_all("/workspace");
    let _ = std::fs::create_dir_all("/run/crucible");

    mount_fs("proc", "/proc", "proc", 0, None);
    mount_fs("sysfs", "/sys", "sysfs", 0, None);
    mount_fs("devtmpfs", "/dev", "devtmpfs", 0, None);
    // Match the /dev surface docker exposes by default — Node SEA / V8
    // expects /dev/shm and /dev/pts to exist on Linux.
    let _ = std::fs::create_dir_all("/dev/shm");
    let _ = std::fs::create_dir_all("/dev/pts");
    mount_fs("tmpfs", "/dev/shm", "tmpfs", 0, None);
    mount_fs("devpts", "/dev/pts", "devpts", 0, None);
    mount_fs("tmpfs", "/tmp", "tmpfs", 0, None);
    mount_fs("tmpfs", "/run", "tmpfs", 0, None);
    // Rootfs is mounted read-only; agents that write under HOME (claude-code:
    // .claude.json, .claude/) need a writable HOME. Mount tmpfs at /root.
    let _ = std::fs::create_dir_all("/root");
    mount_fs("tmpfs", "/root", "tmpfs", 0, None);
}

fn mount_workspace() {
    // /dev/vdb is the workspace ext4 block device attached by Firecracker.
    mount_fs("/dev/vdb", "/workspace", "ext4", libc::MS_RELATIME as u64, None);
}

fn mount_fs(source: &str, target: &str, fs: &str, flags: u64, data: Option<&str>) {
    let src = CString::new(source).unwrap();
    let tgt = CString::new(target).unwrap();
    let typ = CString::new(fs).unwrap();
    let data_ptr = data
        .map(|d| CString::new(d).unwrap())
        .map(|cs| cs.as_ptr() as *const c_void)
        .unwrap_or(std::ptr::null());

    let ret = unsafe {
        libc::mount(src.as_ptr(), tgt.as_ptr(), typ.as_ptr(), flags as libc::c_ulong, data_ptr)
    };
    if ret != 0 {
        let err = io::Error::last_os_error();
        eprintln!("crucible-init: mount {source} → {target} failed: {err}");
    }
}

// ─── Vsock ─────────────────────────────────────────────────────────────────

fn vsock_socket() -> io::Result<RawFd> {
    let fd = unsafe { libc::socket(AF_VSOCK, SOCK_STREAM, 0) };
    if fd < 0 { return Err(io::Error::last_os_error()); }
    Ok(fd)
}

fn vsock_connect(cid: u32, port: u32) -> io::Result<RawFd> {
    let fd = vsock_socket()?;
    let addr = SockaddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: cid,
        svm_zero: [0u8; 4],
    };
    let ret = unsafe {
        libc::connect(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            mem::size_of::<SockaddrVm>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

fn vsock_accept(port: u32) -> io::Result<RawFd> {
    let fd = vsock_socket()?;
    let addr = SockaddrVm {
        svm_family: AF_VSOCK as u16,
        svm_reserved1: 0,
        svm_port: port,
        svm_cid: VMADDR_CID_ANY,
        svm_zero: [0u8; 4],
    };
    let ret = unsafe {
        libc::bind(
            fd,
            &addr as *const SockaddrVm as *const libc::sockaddr,
            mem::size_of::<SockaddrVm>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::listen(fd, 1) };
    let conn = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    unsafe { libc::close(fd) };
    if conn < 0 { return Err(io::Error::last_os_error()); }
    Ok(conn)
}

// ─── Fork + exec ───────────────────────────────────────────────────────────

/// Returns (child_pid, stdout_read_fd, stderr_read_fd).
///
/// stdin  = /dev/null  → isatty(0)=false; no input source.
/// stdout = pipe       → isatty(1)=false so TUI agents (Ink/claude-code) stay in
///                        non-interactive streaming mode; pipe read end is
///                        returned as stdout_r.
/// stderr = pipe       → forwarded to stderr vsock.
fn fork_exec(spec: &InitSpec) -> (pid_t, RawFd, RawFd) {
    let mut stdout_pipe = [0i32; 2];
    let mut stderr_pipe = [0i32; 2];
    unsafe {
        libc::pipe2(stdout_pipe.as_mut_ptr(), libc::O_CLOEXEC);
        libc::pipe2(stderr_pipe.as_mut_ptr(), libc::O_CLOEXEC);
    }

    let args: Vec<CString> = spec.cmd.iter()
        .map(|s| CString::new(s.as_str()).unwrap())
        .collect();
    let argv: Vec<*const libc::c_char> = args.iter()
        .map(|cs| cs.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Build envp without duplicate keys: spec.env wins, then crucible defaults,
    // then PID-1's inherited env. De-duplicate so getenv-order assumptions
    // can't bite us.
    let crucible_defaults: &[(&str, &str)] = &[("HOME", "/root")];
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut env_pairs: Vec<(String, String)> = Vec::new();
    for (k, v) in spec.env.iter() {
        if seen.insert(k.clone()) {
            env_pairs.push((k.clone(), v.clone()));
        }
    }
    for (k, v) in crucible_defaults.iter() {
        if seen.insert((*k).to_string()) {
            env_pairs.push(((*k).to_string(), (*v).to_string()));
        }
    }
    for (k, v) in std::env::vars() {
        // crucible_spec is a base64 blob containing secrets; never forward to
        // the agent. Other kernel-cmdline-derived vars are filtered defensively.
        if k == "crucible_spec" || k.starts_with("crucible_") {
            continue;
        }
        if seen.insert(k.clone()) {
            env_pairs.push((k, v));
        }
    }
    // In debug mode, log the final envp so we can verify precedence.
    // Redact anything that smells like a secret; HOME/PATH/TERM/LANG are visible.
    if DEBUG_ENABLED.load(Ordering::Relaxed) {
        let display: Vec<(String, String)> = env_pairs.iter().map(|(k, v)| {
            let lk = k.to_ascii_lowercase();
            let redact = lk.contains("key") || lk.contains("token") || lk.contains("secret") || lk.contains("pass");
            let shown = if redact { format!("<redacted len={}>", v.len()) } else { v.clone() };
            (k.clone(), shown)
        }).collect();
        dbg(&format!("execvpe envp = {:?}", display));
    }
    let envp: Vec<CString> = env_pairs.iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")).unwrap())
        .collect();
    let envp_ptrs: Vec<*const libc::c_char> = envp.iter()
        .map(|cs| cs.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let pid = unsafe { libc::fork() };
    match pid {
        -1 => panic!("fork failed: {}", io::Error::last_os_error()),
        0 => {
            unsafe {
                // New session; no controlling terminal.
                libc::setsid();

                // Match the OCI image's WORKDIR. Adapters like claude-code
                // derive memory/session paths from cwd and can fail silently
                // when started at "/".
                let ws = b"/workspace\0".as_ptr() as *const libc::c_char;
                libc::chdir(ws);

                // fd 0 = /dev/null    (isatty(0)=false)
                // fd 1 = stdout pipe  (isatty(1)=false → streaming mode)
                // fd 2 = stderr pipe
                let devnull = libc::open(
                    b"/dev/null\0".as_ptr() as *const libc::c_char,
                    libc::O_RDONLY,
                );
                libc::dup2(devnull, libc::STDIN_FILENO);
                libc::dup2(stdout_pipe[1], libc::STDOUT_FILENO);
                libc::dup2(stderr_pipe[1], libc::STDERR_FILENO);

                if devnull > 2 { libc::close(devnull); }
                libc::close(stdout_pipe[0]);
                libc::close(stdout_pipe[1]);
                libc::close(stderr_pipe[0]);
                libc::close(stderr_pipe[1]);

                for fd in 3..256i32 {
                    libc::close(fd);
                }

                libc::execvpe(argv[0], argv.as_ptr(), envp_ptrs.as_ptr());
                libc::exit(127);
            }
        }
        child_pid => {
            unsafe {
                libc::close(stdout_pipe[1]);
                libc::close(stderr_pipe[1]);
            }
            (child_pid, stdout_pipe[0], stderr_pipe[0])
        }
    }
}

// ─── Control loop ──────────────────────────────────────────────────────────

fn control_loop(fd: RawFd, pgid: pid_t, grace_secs: u64) {
    let mut reader = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut buf = String::new();
    let mut tmp = [0u8; 512];
    loop {
        match reader.read(&mut tmp) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.push_str(std::str::from_utf8(&tmp[..n]).unwrap_or(""));
                while let Some(pos) = buf.find('\n') {
                    let line = buf[..pos].trim().to_string();
                    buf.drain(..=pos);
                    dispatch_control(&line, pgid, grace_secs);
                }
            }
        }
    }
}

fn dispatch_control(line: &str, pgid: pid_t, grace_secs: u64) {
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(_) => return,
    };
    match v.get("op").and_then(|o| o.as_str()) {
        Some("stop") => {
            signal_pgid(pgid, SIGTERM);
            // Spawn grace-period escalation thread.
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(grace_secs));
                signal_pgid(pgid, SIGKILL);
            });
        }
        Some("kill") => signal_pgid(pgid, SIGKILL),
        Some("pause") => signal_pgid(pgid, SIGSTOP),
        Some("resume") => signal_pgid(pgid, SIGCONT),
        _ => {}
    }
}

fn signal_pgid(pgid: pid_t, sig: libc::c_int) {
    unsafe { libc::killpg(pgid, sig); }
}

// ─── Zombie reaper ─────────────────────────────────────────────────────────

/// Block until `agent_pid` exits, reaping all other zombies encountered.
/// Returns (exit_code, signal). Exit code is 0 when killed by signal.
fn wait_for_agent(agent_pid: pid_t) -> (i32, i32) {
    loop {
        let mut status = 0i32;
        let reaped = unsafe { libc::waitpid(-1, &mut status, 0) };
        if reaped < 0 {
            // ECHILD → no more children
            return (0, 0);
        }
        if reaped == agent_pid {
            if libc::WIFEXITED(status) {
                return (libc::WEXITSTATUS(status), 0);
            }
            if libc::WIFSIGNALED(status) {
                return (0, libc::WTERMSIG(status));
            }
            return (0, 0);
        }
        // Orphaned child reaped — continue waiting.
    }
}
