//! Per-Run Sandbox networking primitives.
//!
//! The TAP that Firecracker attaches to the guest is a point-to-point link.
//! v1 carves it into a /30 in `169.254.0.0/16` (IPv4 link-local), one /30 per
//! Run, derived deterministically from the Run's id. The host owns `.1` of
//! the /30; the guest's `eth0` owns `.2`.
//!
//! The L7 proxy will bind on the host's `.1` in a follow-up slice so the
//! address injected as `HTTPS_PROXY` is reachable from inside the guest.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunNetwork {
    pub host: Ipv4Addr,
    pub guest: Ipv4Addr,
    pub prefix_len: u8,
}

/// Derive a deterministic /30 IPv4 pair in `169.254.0.0/16` from `run_id`.
///
/// Same `run_id` returns the same pair. Different `run_id`s almost always
/// return different pairs (collision probability ≈ 1/16384 — accepted for
/// v1; `ip addr add` will fail on the second Run and the sandbox bring-up
/// errors out).
///
/// Skips subnet 0 (`169.254.0.0/30`) to avoid the `169.254.0.0`
/// network-address reservation.
pub fn derive_run_network(run_id: &str) -> RunNetwork {
    let subnet_index = subnet_index(run_id);
    let base = subnet_index * 4;
    let octet_2 = ((base >> 8) & 0xff) as u8;
    let octet_3 = (base & 0xff) as u8;
    RunNetwork {
        host: Ipv4Addr::new(169, 254, octet_2, octet_3 + 1),
        guest: Ipv4Addr::new(169, 254, octet_2, octet_3 + 2),
        prefix_len: 30,
    }
}

/// Derive the host-side TAP device name for a Run.
///
/// Kernel interface names are capped at 15 characters (`IFNAMSIZ - 1`). With
/// a `tap-` prefix that leaves 11 chars for the Run id.
///
/// We take those 11 chars from the **end** of `run_id`, not the start. Run ids
/// are ULIDs whose leading 10 characters encode the creation timestamp, so two
/// Runs launched in the same millisecond share an identical prefix — and a
/// prefix-derived name would collide. When that happens the first Firecracker
/// claims the TAP and the second fails to open it (`EBUSY`, surfaced as
/// "Could not create the network device: Open tap device"). The trailing
/// characters come from the ULID's random component, so simultaneously-launched
/// Runs get distinct TAP names regardless of timing.
pub fn derive_tap_name(run_id: &str) -> String {
    let start = run_id.len().saturating_sub(11);
    format!("tap-{}", &run_id[start..])
}

/// Index into the 16,384 available /30 blocks in `169.254.0.0/16`.
/// Returns `[1, 16383]` — index 0 is reserved.
fn subnet_index(run_id: &str) -> u32 {
    // FNV-1a 32-bit. Chosen for stability across Rust versions, unlike
    // `DefaultHasher`. The host-side TAP IP and the guest-side eth0 IP
    // must agree across all callers of this function within a Run, so the
    // hash function cannot change between releases without coordination.
    const FNV_OFFSET: u32 = 0x811c_9dc5;
    const FNV_PRIME: u32 = 0x0100_0193;
    let mut h: u32 = FNV_OFFSET;
    for b in run_id.bytes() {
        h ^= b as u32;
        h = h.wrapping_mul(FNV_PRIME);
    }
    let idx = h & 0x3fff;
    if idx == 0 { 1 } else { idx }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_u32(n: &RunNetwork) -> u32 { u32::from(n.host) }
    fn guest_u32(n: &RunNetwork) -> u32 { u32::from(n.guest) }

    #[test]
    fn derived_pair_is_in_link_local_subnet() {
        let n = derive_run_network("01HZXMSAMPLERUNID0000000000");
        assert_eq!(n.host.octets()[0], 169);
        assert_eq!(n.host.octets()[1], 254);
        assert_eq!(n.guest.octets()[0], 169);
        assert_eq!(n.guest.octets()[1], 254);
        assert_eq!(n.prefix_len, 30);
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_run_network("abc");
        let b = derive_run_network("abc");
        assert_eq!(a, b);
    }

    #[test]
    fn distinct_run_ids_produce_distinct_pairs() {
        let inputs = [
            "01HZXM000000000000000000A0",
            "01HZXM000000000000000000A1",
            "01HZXM000000000000000000A2",
            "01HZXM000000000000000000B0",
            "01HZXMSAMPLERUNID0000000000",
            "another-run-id",
            "yet-another-run-id",
        ];
        let mut seen = std::collections::HashSet::new();
        for input in inputs {
            let n = derive_run_network(input);
            assert!(
                seen.insert((n.host, n.guest)),
                "duplicate /30 for {input:?}: {n:?}"
            );
        }
    }

    #[test]
    fn host_and_guest_are_adjacent_p2p_pair() {
        let n = derive_run_network("any-run-id");
        assert_eq!(guest_u32(&n) - host_u32(&n), 1);
    }

    #[test]
    fn host_is_dot_one_of_a_slash_30() {
        // For a /30, the host octet must end in binary ..01 so that the
        // network is ..00, host ..01, guest ..10, broadcast ..11.
        for input in ["a", "b", "c", "01HZXMSAMPLERUNID0000000000", ""] {
            let n = derive_run_network(input);
            assert_eq!(
                host_u32(&n) & 0x3,
                1,
                "host {} for {input:?} is not aligned to .1 of a /30",
                n.host
            );
            assert_eq!(
                guest_u32(&n) & 0x3,
                2,
                "guest {} for {input:?} is not aligned to .2 of a /30",
                n.guest
            );
        }
    }

    #[test]
    fn subnet_zero_is_skipped() {
        // We can't always find an input that hashes to 0, so test the
        // helper directly: subnet_index never returns 0.
        for input in ["a", "b", "c", "", "01HZXMSAMPLERUNID0000000000"] {
            assert_ne!(subnet_index(input), 0);
        }
    }

    #[test]
    fn subnet_index_stays_within_14_bits() {
        for input in ["a", "b", "longer-input-string", "01HZXMSAMPLERUNID0000000000"] {
            let idx = subnet_index(input);
            assert!(idx <= 0x3fff, "subnet_index out of range: {idx}");
            assert!(idx >= 1);
        }
    }

    #[test]
    fn empty_run_id_does_not_panic() {
        // We never expect an empty run_id in practice, but degrading
        // gracefully is cheaper than special-casing the caller.
        let n = derive_run_network("");
        assert_eq!(n.prefix_len, 30);
        assert_eq!(n.host.octets()[0], 169);
    }

    #[test]
    fn derive_tap_name_uses_trailing_chars_of_run_id() {
        // The 11 chars after `tap-` come from the END of the id, so the
        // timestamp prefix never determines the name.
        assert_eq!(
            derive_tap_name("01HZXMSAMPLERUNID0000000000"),
            "tap-D0000000000"
        );
    }

    #[test]
    fn derive_tap_name_distinct_for_same_millisecond_run_ids() {
        // Regression: these two ULIDs were minted in the same millisecond in a
        // real Run and shared the 10-char timestamp prefix `01KTBRS0AH`. The
        // old prefix-based name produced `tap-01KTBRS0` for both, so the second
        // Firecracker hit EBUSY opening the already-claimed TAP. The trailing
        // random component must make the names distinct.
        let a = derive_tap_name("01KTBRS0AHMEQKV287MN9TFRCX");
        let b = derive_tap_name("01KTBRS0AHTATZGTTV15SWMZXX");
        assert_ne!(a, b, "same-millisecond run ids must yield distinct tap names");
    }

    #[test]
    fn derive_tap_name_handles_short_run_ids() {
        assert_eq!(derive_tap_name("abc"), "tap-abc");
        assert_eq!(derive_tap_name(""), "tap-");
    }

    #[test]
    fn derive_tap_name_fits_in_linux_ifnamsiz() {
        // IFNAMSIZ - 1 = 15 chars max for an interface name.
        for input in ["a", "01HZXMSAMPLERUNID0000000000", "longer-input-string", ""] {
            assert!(
                derive_tap_name(input).len() <= 15,
                "tap name for {input:?} exceeds IFNAMSIZ-1"
            );
        }
    }
}
