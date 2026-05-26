//! Lazy fetch + SHA-256 verify + XDG cache for the guest vmlinux.
//!
//! `ensure_kernel().await` returns the path to a verified vmlinux on disk.
//! Resolution order:
//!   1. `CRUCIBLE_KERNEL` env var → returned as-is, no checks.
//!   2. `$XDG_CACHE_HOME/crucible/kernel/vmlinux-<VERSION>` if SHA-256 matches.
//!   3. Download from the compiled-in URL, SHA-verify, atomic-rename into cache.
//
// Network/async code only runs on Linux where Firecracker is available; suppress
// dead_code on macOS dev builds.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

// ── Compile-time pin: Firecracker-CI guest vmlinux ────────────────────────────
//
// Sourced from the same release line as `kernel/fetch-vmlinux.sh`. Bumping
// either side requires bumping both — the cache file (`vmlinux-<VERSION>`) is
// shared between dev (`./kernel/fetch-vmlinux.sh`) and installed users
// (`ensure_kernel()`), so the version string has to agree.
pub const KERNEL_VERSION: &str = "6.1.155";

#[cfg(target_arch = "x86_64")]
pub const KERNEL_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155";
#[cfg(target_arch = "x86_64")]
pub const KERNEL_SHA256: &str =
    "e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2";

#[cfg(target_arch = "aarch64")]
pub const KERNEL_URL: &str =
    "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/aarch64/vmlinux-6.1.155";
#[cfg(target_arch = "aarch64")]
pub const KERNEL_SHA256: &str =
    "e3544b10603acbf3db492cb52e000d22ba202cb4b63b9add027565683e11c591";

// Dev builds on macOS / other archs compile this module (it's plain Rust), but
// `ensure_kernel()` can't actually fetch a kernel — Firecracker would refuse it
// anyway. Surface that as an actionable error rather than silently embedding a
// wrong-arch URL.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const KERNEL_URL: &str = "";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const KERNEL_SHA256: &str = "";

// ── Cache location ────────────────────────────────────────────────────────────

pub fn cache_dir() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".cache")
        });
    base.join("crucible").join("kernel")
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Resolve the guest vmlinux path, fetching + caching on first use.
pub async fn ensure_kernel() -> Result<PathBuf> {
    if KERNEL_URL.is_empty() {
        bail!(
            "no embedded kernel for this target architecture (only x86_64 and aarch64 are \
             supported); set CRUCIBLE_KERNEL=/path/to/vmlinux to bypass"
        );
    }
    let env_override = std::env::var("CRUCIBLE_KERNEL").ok();
    ensure_kernel_with(
        env_override.as_deref(),
        &cache_dir(),
        KERNEL_URL,
        KERNEL_SHA256,
        KERNEL_VERSION,
    )
    .await
}

/// Implementation core, parameterised for tests.
///
/// `env_override` is treated identically to a runtime `CRUCIBLE_KERNEL` lookup
/// but is passed in so tests can exercise it without mutating process env vars.
async fn ensure_kernel_with(
    env_override: Option<&str>,
    cache_dir: &Path,
    url: &str,
    expected_sha256: &str,
    version: &str,
) -> Result<PathBuf> {
    // Tier 1: explicit override → caller takes responsibility for whatever is
    // at that path. No cache check, no SHA verification, no network.
    if let Some(p) = env_override {
        if !p.is_empty() {
            return Ok(PathBuf::from(p));
        }
    }

    let dest = cache_dir.join(format!("vmlinux-{version}"));

    // Tier 2: cache hit with matching SHA → no network.
    if dest.exists() {
        let actual = sha256_of_file(&dest)
            .await
            .with_context(|| format!("hash cached kernel at {}", dest.display()))?;
        if actual == expected_sha256 {
            return Ok(dest);
        }
        // Cached file is corrupt or stale. Remove and fall through to download.
        eprintln!(
            "[kernel] cached file at {} has wrong SHA-256 \
             (expected {expected_sha256}, got {actual}) — removing and re-downloading",
            dest.display(),
        );
        std::fs::remove_file(&dest)
            .with_context(|| format!("remove corrupt cache file {}", dest.display()))?;
    }

    // Tier 3: download.
    std::fs::create_dir_all(cache_dir)
        .with_context(|| format!("create kernel cache dir {}", cache_dir.display()))?;

    eprintln!("[kernel] downloading vmlinux-{version} from {url}");
    let resp = reqwest::get(url)
        .await
        .with_context(|| format!("download kernel from {url}"))?;
    if !resp.status().is_success() {
        bail!("kernel download from {url} returned HTTP {}", resp.status());
    }
    let bytes = resp
        .bytes()
        .await
        .with_context(|| format!("read kernel body from {url}"))?;

    let tmp = cache_dir.join(format!("vmlinux-{version}.tmp"));
    std::fs::write(&tmp, &bytes)
        .with_context(|| format!("write temp kernel to {}", tmp.display()))?;

    let actual = compute_sha256(&bytes);
    if actual != expected_sha256 {
        let _ = std::fs::remove_file(&tmp);
        bail!(
            "kernel SHA-256 mismatch on download from {url}: \
             expected {expected_sha256}, got {actual}"
        );
    }

    std::fs::rename(&tmp, &dest)
        .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;

    Ok(dest)
}

// ── Hashing helpers ───────────────────────────────────────────────────────────

async fn sha256_of_file(path: &Path) -> Result<String> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("read {}", path.display()))?;
    Ok(compute_sha256(&bytes))
}

fn compute_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    /// Spin up a tiny HTTP/1.1 server that responds to one request with
    /// `status` + `body`, then closes. Returns the bound address and a counter
    /// the test can read to confirm whether a request actually landed.
    async fn spawn_mock(
        status_line: &'static str,
        body: Vec<u8>,
    ) -> (SocketAddr, Arc<AtomicUsize>, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_clone = hits.clone();
        let h = tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                hits_clone.fetch_add(1, Ordering::SeqCst);
                // Drain request headers — stop at the empty line.
                let mut buf = [0u8; 4096];
                let mut total = 0usize;
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    total += n;
                    // Crude end-of-headers check.
                    if buf[..total.min(buf.len())]
                        .windows(4)
                        .any(|w| w == b"\r\n\r\n")
                    {
                        break;
                    }
                    if total >= buf.len() {
                        break;
                    }
                }
                let header = format!(
                    "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len(),
                );
                let _ = sock.write_all(header.as_bytes()).await;
                let _ = sock.write_all(&body).await;
                let _ = sock.shutdown().await;
            }
        });
        (addr, hits, h)
    }

    fn sha_hex(bytes: &[u8]) -> String {
        compute_sha256(bytes)
    }

    // Cycle 1: CRUCIBLE_KERNEL override returns the path verbatim and makes
    // no network request, no cache check.
    #[tokio::test]
    async fn env_override_returns_path_unverified_and_skips_network() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("crucible/kernel");
        // Server is set up but the override should make us bypass it.
        let (addr, hits, h) = spawn_mock("500 Internal Server Error", b"never read".to_vec()).await;

        let path = ensure_kernel_with(
            Some("/some/explicit/vmlinux"),
            &cache,
            &format!("http://{addr}/vmlinux"),
            "0000000000000000000000000000000000000000000000000000000000000000",
            "9.9.9",
        )
        .await
        .unwrap();

        assert_eq!(path, PathBuf::from("/some/explicit/vmlinux"));
        assert_eq!(hits.load(Ordering::SeqCst), 0, "no HTTP request expected");
        // Cache dir should not have been created either.
        assert!(!cache.exists(), "cache dir should not be touched");
        h.abort();
    }

    // Cycle 2: empty env override falls through to cache/download (an env var
    // set to empty string should not short-circuit).
    #[tokio::test]
    async fn empty_env_override_does_not_short_circuit() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("crucible/kernel");
        let body = b"vmlinux-payload".to_vec();
        let want = sha_hex(&body);
        let (addr, hits, h) = spawn_mock("200 OK", body).await;

        let path = ensure_kernel_with(
            Some(""),
            &cache,
            &format!("http://{addr}/vmlinux"),
            &want,
            "9.9.9",
        )
        .await
        .unwrap();

        assert_eq!(path, cache.join("vmlinux-9.9.9"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        h.abort();
    }

    // Cycle 3: cache hit + matching SHA → no network request.
    #[tokio::test]
    async fn cache_hit_skips_network() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("crucible/kernel");
        std::fs::create_dir_all(&cache).unwrap();
        let payload = b"already cached payload".to_vec();
        let dest = cache.join("vmlinux-9.9.9");
        std::fs::write(&dest, &payload).unwrap();
        let expected_sha = sha_hex(&payload);

        let (addr, hits, h) = spawn_mock("500 Internal Server Error", b"unused".to_vec()).await;

        let path = ensure_kernel_with(
            None,
            &cache,
            &format!("http://{addr}/vmlinux"),
            &expected_sha,
            "9.9.9",
        )
        .await
        .unwrap();

        assert_eq!(path, dest);
        assert_eq!(hits.load(Ordering::SeqCst), 0, "cache hit should skip HTTP");
        h.abort();
    }

    // Cycle 4: cache miss + good download → file written + path returned.
    #[tokio::test]
    async fn cache_miss_downloads_and_writes_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("crucible/kernel");
        let body = b"fresh kernel bytes".to_vec();
        let want = sha_hex(&body);
        let (addr, hits, h) = spawn_mock("200 OK", body.clone()).await;

        let path = ensure_kernel_with(
            None,
            &cache,
            &format!("http://{addr}/vmlinux"),
            &want,
            "9.9.9",
        )
        .await
        .unwrap();

        assert_eq!(path, cache.join("vmlinux-9.9.9"));
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, body);
        // Tmp file should be gone (atomic rename).
        assert!(!cache.join("vmlinux-9.9.9.tmp").exists());
        h.abort();
    }

    // Cycle 5: cache miss + SHA mismatch on download → tmp removed, error
    // names both digests.
    #[tokio::test]
    async fn cache_miss_bad_sha_removes_tmp_and_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("crucible/kernel");
        let body = b"tampered bytes".to_vec();
        let actual = sha_hex(&body);
        let expected = "1111111111111111111111111111111111111111111111111111111111111111";
        let (addr, _hits, h) = spawn_mock("200 OK", body).await;

        let err = ensure_kernel_with(
            None,
            &cache,
            &format!("http://{addr}/vmlinux"),
            expected,
            "9.9.9",
        )
        .await
        .unwrap_err();

        let msg = format!("{err:#}");
        assert!(msg.contains("SHA-256 mismatch"), "{msg}");
        assert!(msg.contains(expected), "{msg}");
        assert!(msg.contains(&actual), "{msg}");
        // Neither the cache file nor the tmp file should be left behind.
        assert!(!cache.join("vmlinux-9.9.9").exists());
        assert!(!cache.join("vmlinux-9.9.9.tmp").exists());
        h.abort();
    }

    // Cycle 6: corrupt cache → removed and re-downloaded (this exercises the
    // cache-side mismatch branch).
    #[tokio::test]
    async fn corrupt_cache_is_replaced_by_fresh_download() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("crucible/kernel");
        std::fs::create_dir_all(&cache).unwrap();
        // Pre-populate cache with wrong contents.
        let dest = cache.join("vmlinux-9.9.9");
        std::fs::write(&dest, b"WRONG").unwrap();

        let good = b"GOOD".to_vec();
        let want = sha_hex(&good);
        let (addr, hits, h) = spawn_mock("200 OK", good.clone()).await;

        let path = ensure_kernel_with(
            None,
            &cache,
            &format!("http://{addr}/vmlinux"),
            &want,
            "9.9.9",
        )
        .await
        .unwrap();

        assert_eq!(path, dest);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "should re-download");
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, good);
        h.abort();
    }

    // Cycle 7: network failure (HTTP 500) → error names the URL.
    #[tokio::test]
    async fn http_500_returns_error_naming_the_url() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("crucible/kernel");
        let (addr, _hits, h) = spawn_mock("500 Internal Server Error", b"".to_vec()).await;

        let url = format!("http://{addr}/vmlinux");
        let err = ensure_kernel_with(
            None,
            &cache,
            &url,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "9.9.9",
        )
        .await
        .unwrap_err();

        let msg = format!("{err:#}");
        assert!(msg.contains(&url), "error should name URL: {msg}");
        assert!(msg.contains("500"), "{msg}");
        h.abort();
    }

    // Cycle 8: connect failure → error names the URL (target a port nothing
    // listens on).
    #[tokio::test]
    async fn connect_failure_returns_error_naming_the_url() {
        let tmp = tempfile::tempdir().unwrap();
        let cache = tmp.path().join("crucible/kernel");
        // Bind + drop a listener to get a port that's almost certainly free
        // immediately after.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://{dead_addr}/vmlinux");

        let err = ensure_kernel_with(
            None,
            &cache,
            &url,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "9.9.9",
        )
        .await
        .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains(&url), "error should name URL: {msg}");
    }

    // Cycle 9: cache_dir() honours XDG_CACHE_HOME.
    #[test]
    fn cache_dir_layout_matches_fetch_script() {
        // Compute manually so the test asserts on the SHAPE rather than the
        // implementation. We don't mutate env (parallel tests); instead just
        // verify the result ends with the expected suffix when the env var
        // is what it currently is.
        let p = cache_dir();
        let s = p.to_string_lossy();
        assert!(
            s.ends_with("crucible/kernel"),
            "cache_dir should end in crucible/kernel, got {s}"
        );
    }

    // Cycle 10: compile-time arch constants are populated for the host arch.
    #[test]
    fn arch_constants_are_set_on_supported_targets() {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            assert!(KERNEL_URL.starts_with("https://"), "URL: {KERNEL_URL}");
            assert!(KERNEL_URL.ends_with(&format!("vmlinux-{KERNEL_VERSION}")));
            assert_eq!(KERNEL_SHA256.len(), 64);
            assert!(KERNEL_SHA256.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    // Cycle 11: x86_64 and aarch64 URLs encode their architecture in the path.
    #[test]
    fn arch_constants_encode_architecture_in_url() {
        #[cfg(target_arch = "x86_64")]
        assert!(KERNEL_URL.contains("/x86_64/"), "x86_64 URL: {KERNEL_URL}");
        #[cfg(target_arch = "aarch64")]
        assert!(KERNEL_URL.contains("/aarch64/"), "aarch64 URL: {KERNEL_URL}");
    }
}
