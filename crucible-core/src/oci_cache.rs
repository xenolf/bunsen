//! OCI image pull → ext4 rootfs cache.
//!
//! `resolve_rootfs(image_ref)` → PathBuf to a cached .ext4 file.
//! Cache: `${XDG_CACHE_HOME:-~/.cache}/crucible/rootfs/<sha256hex>.ext4`.
//
// Network/async code only runs on Linux where Firecracker is available.
// Suppress dead_code on macOS dev builds.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use tokio::process::Command;

// ── Cache location ─────────────────────────────────────────────────────────────

pub fn cache_dir() -> PathBuf {
    let base = std::env::var("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            PathBuf::from(home).join(".cache")
        });
    base.join("crucible").join("rootfs")
}

// ── Image reference parsing ────────────────────────────────────────────────────

/// Parsed OCI image reference: `registry/name@sha256:<64hex>`.
#[derive(Debug, Clone, PartialEq)]
pub struct OciImageRef {
    pub registry: String,
    pub name: String,
    /// Full digest, e.g. `sha256:abc123...`
    pub digest: String,
}

impl OciImageRef {
    /// Parse an OCI image reference string.
    ///
    /// Supported format: `[registry/]name@sha256:<64hex>`
    /// e.g. `ghcr.io/org/image@sha256:abc123...`
    pub fn parse(s: &str) -> Result<Self> {
        let at = s.rfind('@').ok_or_else(|| {
            anyhow!("OCI reference must be digest-pinned (missing '@'): {s}")
        })?;
        let (path, digest_with_at) = s.split_at(at);
        let digest = &digest_with_at[1..]; // strip '@'

        if !digest.starts_with("sha256:") {
            bail!("OCI digest must use sha256 algorithm: {digest}");
        }
        let hex = digest.strip_prefix("sha256:").unwrap();
        if hex.len() != 64 {
            bail!("OCI sha256 digest must be exactly 64 hex chars, got {}: {hex}", hex.len());
        }
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("OCI sha256 digest contains non-hex chars: {hex}");
        }

        let (registry, name) = split_registry_and_name(path);

        Ok(OciImageRef {
            registry: registry.to_string(),
            name: name.to_string(),
            digest: digest.to_string(),
        })
    }

    pub fn digest_hex(&self) -> &str {
        self.digest.strip_prefix("sha256:").unwrap()
    }
}

/// Split `path` into (registry, name).
/// A registry segment contains a `.` or `:` or is `localhost`.
fn split_registry_and_name(path: &str) -> (&str, &str) {
    if let Some(slash) = path.find('/') {
        let candidate = &path[..slash];
        let is_registry = candidate.contains('.')
            || candidate.contains(':')
            || candidate == "localhost";
        if is_registry {
            return (&path[..slash], &path[slash + 1..]);
        }
    }
    ("registry-1.docker.io", path)
}

// ── Resolve rootfs (main entry point) ─────────────────────────────────────────

/// Resolve an OCI image reference to a cached ext4 path.
///
/// On first call: pull from registry, verify digest, flatten layers, create ext4.
/// On subsequent calls: return cached path immediately.
pub async fn resolve_rootfs(image_ref: &str) -> Result<PathBuf> {
    let r = OciImageRef::parse(image_ref)?;
    let cache_path = cache_dir().join(format!("{}.ext4", r.digest_hex()));

    if cache_path.exists() {
        eprintln!("[oci] cache hit: {}", cache_path.display());
        return Ok(cache_path);
    }

    eprintln!("[oci] pulling {image_ref}");
    let tmp = tempfile::TempDir::new().context("create temp dir for OCI extraction")?;
    pull_and_flatten(&r, tmp.path()).await.context("pull and flatten OCI image")?;

    eprintln!("[oci] creating ext4 rootfs…");
    std::fs::create_dir_all(cache_dir()).context("create rootfs cache dir")?;
    create_ext4_from_dir(tmp.path(), &cache_path)
        .await
        .context("create rootfs ext4")?;

    Ok(cache_path)
}

// ── OCI pull ──────────────────────────────────────────────────────────────────

async fn pull_and_flatten(r: &OciImageRef, dest: &Path) -> Result<()> {
    let client = build_http_client()?;

    // pull_manifest handles the auth challenge internally; it returns the
    // bearer token it obtained (if any) so blob pulls can reuse it.
    let (manifest_json, actual_digest, token) = pull_manifest(&client, r).await?;

    if actual_digest != r.digest {
        bail!(
            "OCI digest mismatch: expected {}, got {}",
            r.digest,
            actual_digest
        );
    }

    let manifest: serde_json::Value =
        serde_json::from_str(&manifest_json).context("parse OCI manifest JSON")?;

    // Handle manifest lists (multi-arch): pick linux/amd64.
    let manifest_for_layers =
        resolve_image_manifest(&client, r, token.as_deref(), &manifest).await?;

    let layers = manifest_for_layers["layers"]
        .as_array()
        .ok_or_else(|| anyhow!("OCI manifest has no 'layers' field"))?;

    eprintln!("[oci] {} layer(s)", layers.len());

    for (i, layer) in layers.iter().enumerate() {
        let layer_digest = layer["digest"]
            .as_str()
            .ok_or_else(|| anyhow!("layer {i} has no digest"))?;
        let layer_size = layer["size"].as_u64().unwrap_or(0);
        eprintln!(
            "[oci] layer {}/{}: {} ({} bytes compressed)",
            i + 1,
            layers.len(),
            layer_digest,
            layer_size
        );
        let data = pull_blob(&client, r, layer_digest, token.as_deref())
            .await
            .with_context(|| format!("pull layer {layer_digest}"))?;
        apply_layer(dest, &data).with_context(|| format!("apply layer {i}"))?;
    }

    Ok(())
}

/// If `manifest` is a manifest list, fetch and return the linux/amd64 image manifest.
/// Otherwise return the manifest unchanged.
async fn resolve_image_manifest(
    client: &reqwest::Client,
    r: &OciImageRef,
    token: Option<&str>,
    manifest: &serde_json::Value,
) -> Result<serde_json::Value> {
    let media_type = manifest["mediaType"].as_str().unwrap_or("");
    let is_list = media_type
        == "application/vnd.docker.distribution.manifest.list.v2+json"
        || media_type == "application/vnd.oci.image.index.v1+json";

    if !is_list {
        return Ok(manifest.clone());
    }

    let manifests = manifest["manifests"]
        .as_array()
        .ok_or_else(|| anyhow!("manifest list has no 'manifests' array"))?;

    let child = manifests
        .iter()
        .find(|m| {
            let p = &m["platform"];
            p["os"].as_str() == Some("linux") && p["architecture"].as_str() == Some("amd64")
        })
        .ok_or_else(|| anyhow!("no linux/amd64 manifest in manifest list"))?;

    let child_digest = child["digest"]
        .as_str()
        .ok_or_else(|| anyhow!("child manifest missing digest"))?;

    let url = format!(
        "{}://{}/v2/{}/manifests/{}",
        registry_scheme(&r.registry), r.registry, r.name, child_digest
    );
    let mut req = client
        .get(&url)
        .header("Accept", OCI_ACCEPT_HEADERS.join(", "));
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let resp = req.send().await.context("pull child manifest")?;
    if !resp.status().is_success() {
        bail!("child manifest returned {}", resp.status());
    }
    let body = resp.text().await?;
    serde_json::from_str(&body).context("parse child manifest")
}

const OCI_ACCEPT_HEADERS: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
];

fn build_http_client() -> Result<reqwest::Client> {
    reqwest::ClientBuilder::new()
        .user_agent("crucible-core/0.1")
        .build()
        .context("build HTTP client")
}

/// Use plain HTTP for localhost / loopback registries; HTTPS for everything else.
pub fn registry_scheme(registry: &str) -> &'static str {
    let host = registry.split(':').next().unwrap_or(registry);
    if host == "localhost" || host == "127.0.0.1" || host == "::1" {
        "http"
    } else {
        "https"
    }
}

pub fn parse_www_authenticate(www_auth: &str) -> Result<(String, String)> {
    let realm = parse_www_auth_field(www_auth, "realm")?;
    let service = parse_www_auth_field(www_auth, "service").unwrap_or_default();
    Ok((realm, service))
}

fn parse_www_auth_field(header: &str, field: &str) -> Result<String> {
    let needle = format!("{field}=\"");
    let start = header
        .find(&needle)
        .ok_or_else(|| anyhow!("no {field}= in Www-Authenticate: {header}"))?
        + needle.len();
    let rest = &header[start..];
    let end = rest
        .find('"')
        .ok_or_else(|| anyhow!("unterminated {field} value in Www-Authenticate"))?;
    Ok(rest[..end].to_string())
}

async fn fetch_token_from_challenge(
    client: &reqwest::Client,
    www_auth: &str,
    name: &str,
) -> Result<String> {
    let (realm, service) = parse_www_authenticate(www_auth)?;
    let url = format!("{realm}?scope=repository:{name}:pull&service={service}");
    let resp = client
        .get(&url)
        .send()
        .await
        .context("fetch registry token")?;
    if !resp.status().is_success() {
        bail!("token endpoint returned {}", resp.status());
    }
    let body: serde_json::Value = resp.json().await.context("parse token response")?;
    let token = body["token"]
        .as_str()
        .or_else(|| body["access_token"].as_str())
        .ok_or_else(|| anyhow!("no token in response"))?;
    Ok(token.to_string())
}

/// Pull the manifest and compute its sha256 digest.
///
/// Tries unauthenticated first. On 401, reads the Www-Authenticate challenge
/// from *that* response (which contains the correct scope for this specific
/// resource), obtains a Bearer token, then retries.
///
/// Returns `(manifest_json, sha256_digest, Option<bearer_token>)`.
async fn pull_manifest(
    client: &reqwest::Client,
    r: &OciImageRef,
) -> Result<(String, String, Option<String>)> {
    let url = format!(
        "{}://{}/v2/{}/manifests/{}",
        registry_scheme(&r.registry), r.registry, r.name, r.digest
    );

    // First attempt: no credentials.
    let resp = client
        .get(&url)
        .header("Accept", OCI_ACCEPT_HEADERS.join(", "))
        .send()
        .await
        .context("pull manifest")?;

    if resp.status().is_success() {
        let (body, digest) = read_manifest_bytes(resp).await?;
        return Ok((body, digest, None));
    }

    if resp.status() == reqwest::StatusCode::UNAUTHORIZED {
        // Extract the scope-correct challenge from *this* 401 response.
        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        if !www_auth.is_empty() {
            let token = fetch_token_from_challenge(client, &www_auth, &r.name)
                .await
                .context("obtain Bearer token from manifest www-authenticate challenge")?;

            let resp2 = client
                .get(&url)
                .header("Accept", OCI_ACCEPT_HEADERS.join(", "))
                .header("Authorization", format!("Bearer {token}"))
                .send()
                .await
                .context("pull manifest (authenticated)")?;

            if !resp2.status().is_success() {
                bail!(
                    "manifest pull returned {}: {}",
                    resp2.status(),
                    resp2.text().await.unwrap_or_default()
                );
            }
            let (body, digest) = read_manifest_bytes(resp2).await?;
            return Ok((body, digest, Some(token)));
        }
    }

    bail!(
        "manifest pull returned {}: {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    )
}

async fn read_manifest_bytes(resp: reqwest::Response) -> Result<(String, String)> {
    let body_bytes = resp.bytes().await.context("read manifest body")?;
    let mut hasher = Sha256::new();
    hasher.update(&body_bytes);
    let actual_digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    let body_str =
        String::from_utf8(body_bytes.to_vec()).context("manifest is not valid UTF-8")?;
    Ok((body_str, actual_digest))
}

async fn pull_blob(
    client: &reqwest::Client,
    r: &OciImageRef,
    digest: &str,
    token: Option<&str>,
) -> Result<Vec<u8>> {
    let url = format!("{}://{}/v2/{}/blobs/{}", registry_scheme(&r.registry), r.registry, r.name, digest);
    let mut req = client.get(&url);
    if let Some(t) = token {
        req = req.header("Authorization", format!("Bearer {t}"));
    }
    let resp = req.send().await.context("pull blob")?;
    if !resp.status().is_success() {
        bail!("blob pull returned {}", resp.status());
    }
    Ok(resp.bytes().await.context("read blob")?.to_vec())
}

// ── Layer application ─────────────────────────────────────────────────────────

/// Classify a tar entry filename as a whiteout.
pub enum WhiteoutKind {
    /// `.wh..wh..opq` — delete all sibling entries in the parent directory.
    Opaque,
    /// `.wh.<name>` — delete the named sibling.
    Named(String),
    /// Not a whiteout.
    None,
}

pub fn classify_whiteout(file_name: &str) -> WhiteoutKind {
    if file_name == ".wh..wh..opq" {
        WhiteoutKind::Opaque
    } else if let Some(name) = file_name.strip_prefix(".wh.") {
        WhiteoutKind::Named(name.to_string())
    } else {
        WhiteoutKind::None
    }
}

fn apply_layer(dest: &Path, layer_data: &[u8]) -> Result<()> {
    use flate2::read::GzDecoder;
    use tar::Archive;

    let gz = GzDecoder::new(layer_data);
    let mut archive = Archive::new(gz);
    archive.set_preserve_permissions(true);
    archive.set_preserve_mtime(true);
    archive.set_overwrite(true);

    let entries = archive.entries().context("read tar entries")?;

    for entry in entries {
        let mut entry = entry.context("read tar entry")?;
        let path = entry.path().context("entry path")?.to_path_buf();

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        match classify_whiteout(file_name) {
            WhiteoutKind::Opaque => {
                if let Some(parent) = path.parent() {
                    let target = dest.join(parent);
                    if target.exists() {
                        for e in std::fs::read_dir(&target)? {
                            let e = e?;
                            let ep = e.path();
                            if ep.is_dir() {
                                std::fs::remove_dir_all(&ep).ok();
                            } else {
                                std::fs::remove_file(&ep).ok();
                            }
                        }
                    }
                }
            }
            WhiteoutKind::Named(name) => {
                let parent = path.parent().unwrap_or(Path::new(""));
                let target = dest.join(parent).join(&name);
                if target.is_dir() {
                    std::fs::remove_dir_all(&target).ok();
                } else {
                    std::fs::remove_file(&target).ok();
                }
            }
            WhiteoutKind::None => {
                entry.unpack_in(dest).context("unpack tar entry")?;
            }
        }
    }

    Ok(())
}

// ── ext4 creation ─────────────────────────────────────────────────────────────

async fn create_ext4_from_dir(source_dir: &Path, output: &Path) -> Result<()> {
    // Measure actual extracted size to right-size the ext4 image.
    let du = Command::new("du")
        .args(["-sm", &source_dir.to_string_lossy()])
        .output()
        .await
        .context("du -sm")?;
    let size_mb: u32 = String::from_utf8_lossy(&du.stdout)
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);

    // 50% headroom + 256 MB for ext4 metadata.
    let padded = (size_mb * 3 / 2).max(512) + 256;
    eprintln!("[oci] image content: {size_mb} MiB → ext4: {padded} MiB");

    let status = Command::new("mkfs.ext4")
        .args([
            "-F",
            "-d",
            &source_dir.to_string_lossy(),
            "-b",
            "4096",
            &output.to_string_lossy(),
            &format!("{padded}M"),
        ])
        .status()
        .await
        .context("mkfs.ext4")?;

    if !status.success() {
        bail!("mkfs.ext4 failed for {}", output.display());
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const HEX64: &str = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

    // Cycle 1: parse a valid GHCR reference.
    #[test]
    fn parse_valid_ghcr_ref() {
        let s = format!("ghcr.io/org/img@sha256:{HEX64}");
        let r = OciImageRef::parse(&s).unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.name, "org/img");
        assert_eq!(r.digest, format!("sha256:{HEX64}"));
        assert_eq!(r.digest_hex(), HEX64);
    }

    // Cycle 2: missing '@' is an error.
    #[test]
    fn parse_ref_missing_digest() {
        let err = OciImageRef::parse("ghcr.io/org/img:latest").unwrap_err();
        assert!(err.to_string().contains("digest-pinned"), "{err}");
    }

    // Cycle 3: non-sha256 digest algorithm.
    #[test]
    fn parse_ref_non_sha256_digest() {
        let err = OciImageRef::parse("ghcr.io/org/img@md5:abc").unwrap_err();
        assert!(err.to_string().contains("sha256"), "{err}");
    }

    // Cycle 4: digest hex too short.
    #[test]
    fn parse_ref_short_digest() {
        let err = OciImageRef::parse("ghcr.io/org/img@sha256:abc").unwrap_err();
        assert!(err.to_string().contains("64 hex"), "{err}");
    }

    // Cycle 5: cache path is derived from digest hex.
    #[test]
    fn cache_path_derived_from_digest() {
        let path = cache_dir().join(format!("{HEX64}.ext4"));
        assert!(path.to_string_lossy().contains(HEX64));
        assert!(path.to_string_lossy().ends_with(".ext4"));
        assert!(path.to_string_lossy().contains("crucible/rootfs"));
    }

    // Cycle 8: parse Www-Authenticate Bearer header.
    #[test]
    fn parse_www_authenticate_bearer() {
        let header = r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:org/img:pull""#;
        let (realm, service) = parse_www_authenticate(header).unwrap();
        assert_eq!(realm, "https://ghcr.io/token");
        assert_eq!(service, "ghcr.io");
    }

    // Cycle 9: opaque whiteout detection.
    #[test]
    fn detect_opaque_whiteout() {
        matches!(classify_whiteout(".wh..wh..opq"), WhiteoutKind::Opaque);
        assert!(matches!(classify_whiteout(".wh..wh..opq"), WhiteoutKind::Opaque));
    }

    // registry_scheme: localhost uses http, everything else uses https.
    #[test]
    fn localhost_uses_http_scheme() {
        assert_eq!(registry_scheme("localhost"), "http");
        assert_eq!(registry_scheme("localhost:5000"), "http");
        assert_eq!(registry_scheme("127.0.0.1:5000"), "http");
        assert_eq!(registry_scheme("ghcr.io"), "https");
        assert_eq!(registry_scheme("registry-1.docker.io"), "https");
    }

    // Cycle 10: regular whiteout detection.
    #[test]
    fn detect_regular_whiteout() {
        match classify_whiteout(".wh.foo") {
            WhiteoutKind::Named(name) => assert_eq!(name, "foo"),
            _ => panic!("expected Named whiteout"),
        }
        assert!(matches!(classify_whiteout("regular_file"), WhiteoutKind::None));
    }
}
