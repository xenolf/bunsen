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

use serde::Deserialize;
use std::net::Ipv4Addr;

/// Per-Run network configuration handed to the guest by the host. Mirrors
/// `crucible_core::sandbox_net::RunNetwork` on the wire (kebab-case JSON).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct GuestNetwork {
    pub guest_ip: Ipv4Addr,
    pub host_ip: Ipv4Addr,
    pub prefix_len: u8,
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
}

#[cfg(target_os = "linux")]
pub use linux::configure_eth0;

#[cfg(not(target_os = "linux"))]
pub fn configure_eth0(_net: &GuestNetwork) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "configure_eth0 is Linux-only",
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
}
