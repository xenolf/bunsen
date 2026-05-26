//! Guest network bring-up for eth0 (Linux-only ioctls).
//!
//! The host hands the guest a /30 IPv4 pair via the kernel cmdline spec
//! ([`GuestNetwork`]). This module assigns the guest's address to `eth0`,
//! marks the link `UP`, and installs a default route via the host's TAP IP.
//!
//! Direct ioctls are used (not a shell-out to `/sbin/ip`) so the bring-up
//! has no dependency on the agent's OCI rootfs — `iproute2` / `busybox` may
//! not be present on every Adapter image, but `crucible-init` itself is the
//! same static binary in every rootfs.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use serde::Deserialize;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;

/// Per-Run network configuration handed to the guest by the host. Mirrors
/// `crucible_core::sandbox_net::RunNetwork` on the wire (kebab-case JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GuestNetwork {
    pub guest_ip: Ipv4Addr,
    pub host_ip: Ipv4Addr,
    pub prefix_len: u8,
}

/// Tmpfs path where the staged `/etc/resolv.conf` body lives before the
/// bind mount lands it at the canonical location. `/run` is tmpfs (mounted
/// by [`crate::init_linux::mount_filesystems`]) so this path is writable
/// even though the rootfs is read-only.
pub const RESOLV_CONF_SCRATCH: &str = "/run/crucible/resolv.conf";

/// Canonical location of the guest's resolver config; bind-mount target.
pub const RESOLV_CONF_TARGET: &str = "/etc/resolv.conf";

/// Render the `/etc/resolv.conf` body that points the guest's libc resolver
/// at the host-side DNS listener on `host_ip:53`.
///
/// One nameserver line, trailing newline. No search domains, no `options`,
/// no comments: an additional line could be parsed by a guest resolver as
/// another (unreachable) nameserver and stall lookups during failover.
pub fn format_resolv_conf(host_ip: Ipv4Addr) -> String {
    format!("nameserver {host_ip}\n")
}

/// Write the resolv.conf body to `scratch_path` (typically [`RESOLV_CONF_SCRATCH`]).
///
/// Creates parent directories if missing and truncates any pre-existing
/// file. This is the platform-independent half of the bring-up; the Linux
/// `install_resolv_conf` ties it to the bind mount.
pub fn stage_resolv_conf(net: &GuestNetwork, scratch_path: &Path) -> io::Result<()> {
    if let Some(parent) = scratch_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(scratch_path, format_resolv_conf(net.host_ip))
}

/// Convert a CIDR prefix length (e.g. 30) into an IPv4 netmask
/// (e.g. 255.255.255.252).
///
/// Saturates at 32. A `prefix_len` of 0 returns `0.0.0.0`.
pub fn prefix_len_to_netmask(prefix_len: u8) -> Ipv4Addr {
    let bits = prefix_len.min(32);
    let mask: u32 = if bits == 0 {
        0
    } else {
        // Shift in a wider type to avoid the 32-bit-shift overflow case.
        (!0u32) << (32 - bits as u32)
    };
    Ipv4Addr::from(mask)
}

// ─── Linux-only bring-up ──────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use libc::{
        c_void, ifreq, sockaddr, sockaddr_in, AF_INET, IFF_RUNNING, IFF_UP,
        SIOCADDRT, SIOCSIFADDR, SIOCSIFFLAGS, SIOCSIFNETMASK, SOCK_DGRAM,
    };
    use std::ffi::CString;
    use std::io;
    use std::mem;
    use std::os::unix::io::RawFd;

    const IFNAME: &str = "eth0";

    /// Bring up `eth0` with the guest IP/netmask and add a default route via
    /// the host's TAP IP.
    ///
    /// Each step is independent: a route-add failure does not undo the
    /// address assignment. Caller is expected to log on error and continue —
    /// the L7 egress slice's enforcement is not yet load-bearing in v1
    /// (slice 10g; nftables L3 is a follow-up).
    pub fn configure_eth0(net: &GuestNetwork) -> io::Result<()> {
        let sock = open_inet_socket()?;
        let result = (|| -> io::Result<()> {
            set_if_addr(sock, IFNAME, net.guest_ip)?;
            set_if_netmask(sock, IFNAME, prefix_len_to_netmask(net.prefix_len))?;
            set_if_up(sock, IFNAME)?;
            add_default_route(sock, net.host_ip)?;
            Ok(())
        })();
        unsafe { libc::close(sock) };
        result
    }

    fn open_inet_socket() -> io::Result<RawFd> {
        let fd = unsafe { libc::socket(AF_INET, SOCK_DGRAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// Populate `ifr_name` with a NUL-terminated copy of `ifname`. Panics if
    /// the name is too long for `IFNAMSIZ` — the only caller passes the
    /// fixed string `"eth0"`.
    fn ifreq_for(ifname: &str) -> ifreq {
        let mut ifr: ifreq = unsafe { mem::zeroed() };
        let cname = CString::new(ifname).expect("ifname has no interior nul");
        let bytes = cname.as_bytes_with_nul();
        assert!(
            bytes.len() <= ifr.ifr_name.len(),
            "ifname too long for IFNAMSIZ"
        );
        for (i, b) in bytes.iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        ifr
    }

    fn sockaddr_in_v4(ip: Ipv4Addr) -> sockaddr_in {
        // Safety: sockaddr_in is plain old data; zeroing is sound.
        let mut sa: sockaddr_in = unsafe { mem::zeroed() };
        sa.sin_family = AF_INET as libc::sa_family_t;
        sa.sin_port = 0;
        sa.sin_addr.s_addr = u32::to_be(u32::from(ip));
        sa
    }

    fn set_if_addr(sock: RawFd, ifname: &str, ip: Ipv4Addr) -> io::Result<()> {
        let mut ifr = ifreq_for(ifname);
        let sa = sockaddr_in_v4(ip);
        unsafe {
            *( &mut ifr.ifr_ifru.ifru_addr as *mut sockaddr as *mut sockaddr_in ) = sa;
        }
        ioctl(sock, SIOCSIFADDR, &mut ifr as *mut _ as *mut c_void)
    }

    fn set_if_netmask(sock: RawFd, ifname: &str, mask: Ipv4Addr) -> io::Result<()> {
        let mut ifr = ifreq_for(ifname);
        let sa = sockaddr_in_v4(mask);
        unsafe {
            *( &mut ifr.ifr_ifru.ifru_netmask as *mut sockaddr as *mut sockaddr_in ) = sa;
        }
        ioctl(sock, SIOCSIFNETMASK, &mut ifr as *mut _ as *mut c_void)
    }

    fn set_if_up(sock: RawFd, ifname: &str) -> io::Result<()> {
        let mut ifr = ifreq_for(ifname);
        // Writing a non-Drop union variant is safe; only reads need `unsafe`.
        ifr.ifr_ifru.ifru_flags = (IFF_UP | IFF_RUNNING) as libc::c_short;
        ioctl(sock, SIOCSIFFLAGS, &mut ifr as *mut _ as *mut c_void)
    }

    fn add_default_route(sock: RawFd, gateway: Ipv4Addr) -> io::Result<()> {
        // `rtentry` is defined for the linux glibc + musl + uclibc targets.
        // We build the request by hand because crucible-init targets musl.
        let mut rt: libc::rtentry = unsafe { mem::zeroed() };
        write_sockaddr(&mut rt.rt_dst, Ipv4Addr::UNSPECIFIED);
        write_sockaddr(&mut rt.rt_gateway, gateway);
        write_sockaddr(&mut rt.rt_genmask, Ipv4Addr::UNSPECIFIED);
        // RTF_UP (0x0001) | RTF_GATEWAY (0x0002)
        rt.rt_flags = 0x0001 | 0x0002;
        ioctl(sock, SIOCADDRT, &mut rt as *mut _ as *mut c_void)
    }

    fn write_sockaddr(dst: &mut sockaddr, ip: Ipv4Addr) {
        let sa = sockaddr_in_v4(ip);
        unsafe { *(dst as *mut sockaddr as *mut sockaddr_in) = sa };
    }

    fn ioctl(fd: RawFd, request: libc::c_ulong, arg: *mut c_void) -> io::Result<()> {
        let ret = unsafe { libc::ioctl(fd, request as _, arg) };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Stage `nameserver <host_ip>` to a tmpfs file under `/run/crucible/`
    /// and bind-mount it over `/etc/resolv.conf` so the guest's libc
    /// resolver routes through the host-side DNS listener.
    ///
    /// The rootfs is mounted read-only at the Firecracker level, so writing
    /// `/etc/resolv.conf` directly fails with EROFS — the bind mount over
    /// the existing file is what makes the change visible.
    ///
    /// Requires that `/etc/resolv.conf` already exists as a regular file in
    /// the rootfs (standard for Alpine/Debian/Ubuntu OCI base images). If
    /// the target is missing or is a symlink, the mount fails and the
    /// caller is expected to log + continue.
    pub fn install_resolv_conf(net: &GuestNetwork) -> io::Result<()> {
        let scratch = std::path::Path::new(super::RESOLV_CONF_SCRATCH);
        super::stage_resolv_conf(net, scratch)?;
        bind_mount_file(scratch, std::path::Path::new(super::RESOLV_CONF_TARGET))
    }

    /// `mount(source, target, NULL, MS_BIND, NULL)`. Source and target must
    /// both exist; for file-over-file binds the kernel just substitutes the
    /// inode in dentry lookups under `target`.
    fn bind_mount_file(source: &std::path::Path, target: &std::path::Path) -> io::Result<()> {
        let src = CString::new(source.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let tgt = CString::new(target.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // Empty filesystem type and data are ignored for MS_BIND.
        let typ = CString::new("").unwrap();
        let ret = unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                typ.as_ptr(),
                libc::MS_BIND,
                std::ptr::null(),
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;

#[cfg(target_os = "linux")]
pub use linux::{configure_eth0, install_resolv_conf};

#[cfg(not(target_os = "linux"))]
pub fn configure_eth0(_net: &GuestNetwork) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "configure_eth0 is Linux-only",
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn install_resolv_conf(_net: &GuestNetwork) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "install_resolv_conf is Linux-only",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_len_to_netmask_classics() {
        assert_eq!(
            prefix_len_to_netmask(8),
            Ipv4Addr::new(255, 0, 0, 0),
        );
        assert_eq!(
            prefix_len_to_netmask(16),
            Ipv4Addr::new(255, 255, 0, 0),
        );
        assert_eq!(
            prefix_len_to_netmask(24),
            Ipv4Addr::new(255, 255, 255, 0),
        );
    }

    #[test]
    fn prefix_len_to_netmask_slash_thirty() {
        // /30 is the per-Run sandbox prefix.
        assert_eq!(
            prefix_len_to_netmask(30),
            Ipv4Addr::new(255, 255, 255, 252),
        );
    }

    #[test]
    fn prefix_len_to_netmask_edges() {
        assert_eq!(prefix_len_to_netmask(0), Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(
            prefix_len_to_netmask(32),
            Ipv4Addr::new(255, 255, 255, 255),
        );
        // Saturates rather than panicking on the >32 case (defensive).
        assert_eq!(
            prefix_len_to_netmask(33),
            Ipv4Addr::new(255, 255, 255, 255),
        );
    }

    #[test]
    fn guest_network_deserializes_kebab_case_wire_shape() {
        // The host emits `network` as a kebab-case JSON object inside the
        // InitSpec; the guest must accept it verbatim.
        let json = r#"{
            "guest-ip": "169.254.42.2",
            "host-ip":  "169.254.42.1",
            "prefix-len": 30
        }"#;
        let n: GuestNetwork = serde_json::from_str(json).unwrap();
        assert_eq!(n.guest_ip, Ipv4Addr::new(169, 254, 42, 2));
        assert_eq!(n.host_ip, Ipv4Addr::new(169, 254, 42, 1));
        assert_eq!(n.prefix_len, 30);
    }

    #[test]
    fn guest_network_deserialization_rejects_bad_ip() {
        let bad = r#"{
            "guest-ip": "not-an-ip",
            "host-ip":  "169.254.42.1",
            "prefix-len": 30
        }"#;
        assert!(serde_json::from_str::<GuestNetwork>(bad).is_err());
    }

    #[test]
    fn guest_network_layout_for_a_slash_thirty() {
        // The shape this struct is meant to carry across the host/guest seam:
        // host owns .1, guest owns .2, netmask /30.
        let net = GuestNetwork {
            guest_ip: Ipv4Addr::new(169, 254, 42, 2),
            host_ip: Ipv4Addr::new(169, 254, 42, 1),
            prefix_len: 30,
        };
        assert_eq!(
            prefix_len_to_netmask(net.prefix_len),
            Ipv4Addr::new(255, 255, 255, 252),
        );
    }

    // ─── /etc/resolv.conf shape + staging ─────────────────────────────────

    #[test]
    fn format_resolv_conf_emits_single_nameserver_line() {
        let s = format_resolv_conf(Ipv4Addr::new(169, 254, 42, 1));
        assert_eq!(s, "nameserver 169.254.42.1\n");
    }

    #[test]
    fn format_resolv_conf_has_trailing_newline() {
        // glibc's resolv.conf parser stops at the first line without a
        // terminating newline on some versions; always emit one.
        let s = format_resolv_conf(Ipv4Addr::new(10, 0, 0, 53));
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn format_resolv_conf_emits_exactly_one_line() {
        // No options, no search domains, no comments — just the nameserver.
        // Extra lines would either be ignored (best case) or interpreted by
        // a guest's resolv.conf parser as additional servers.
        let s = format_resolv_conf(Ipv4Addr::new(169, 254, 1, 1));
        assert_eq!(s.lines().count(), 1);
    }

    #[test]
    fn format_resolv_conf_uses_dotted_quad_form() {
        // Display impl on Ipv4Addr already produces the canonical form; this
        // test pins the wire format so a future refactor can't accidentally
        // emit `nameserver 0xa9fe...` or similar.
        let s = format_resolv_conf(Ipv4Addr::new(8, 8, 8, 8));
        assert!(s.contains("8.8.8.8"));
        assert!(!s.contains("0x"));
    }

    #[test]
    fn stage_resolv_conf_writes_content_to_scratch_path() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("resolv.conf");
        let net = GuestNetwork {
            guest_ip: Ipv4Addr::new(169, 254, 42, 2),
            host_ip: Ipv4Addr::new(169, 254, 42, 1),
            prefix_len: 30,
        };
        stage_resolv_conf(&net, &scratch).unwrap();
        let on_disk = std::fs::read_to_string(&scratch).unwrap();
        assert_eq!(on_disk, "nameserver 169.254.42.1\n");
    }

    #[test]
    fn stage_resolv_conf_overwrites_existing_file() {
        // The scratch path may survive across runs in the same VM if init
        // somehow re-entered. Stage must truncate and rewrite, not append.
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("resolv.conf");
        std::fs::write(&scratch, b"stale content\n").unwrap();
        let net = GuestNetwork {
            guest_ip: Ipv4Addr::new(169, 254, 42, 2),
            host_ip: Ipv4Addr::new(169, 254, 0, 5),
            prefix_len: 30,
        };
        stage_resolv_conf(&net, &scratch).unwrap();
        let on_disk = std::fs::read_to_string(&scratch).unwrap();
        assert_eq!(on_disk, "nameserver 169.254.0.5\n");
    }

    #[test]
    fn stage_resolv_conf_creates_parent_dir_if_missing() {
        // Caller may pass /run/crucible/resolv.conf before mount_filesystems
        // has reached /run/crucible. Defensive: create parents.
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("nested").join("resolv.conf");
        let net = GuestNetwork {
            guest_ip: Ipv4Addr::new(169, 254, 42, 2),
            host_ip: Ipv4Addr::new(169, 254, 42, 1),
            prefix_len: 30,
        };
        stage_resolv_conf(&net, &scratch).unwrap();
        assert!(scratch.exists());
    }
}
