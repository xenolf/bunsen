# PyPI distribution via pre-built platform wheels

Bunsen is distributed on PyPI as platform-specific wheels containing a pre-compiled `bunsen-core` binary. No Rust toolchain is required at install time.

## Why

- **ADR 0002 established the subprocess seam.** `bunsen-core` is a standalone binary, not a Python extension. maturin can build wheels containing a Rust binary without PyO3; we use that capability rather than adding a second distribution mechanism.
- **Compile-on-install is not viable for end users.** Requiring a Rust toolchain at `pip install` time is a hard barrier for the User Script audience.
- **Post-install download hooks are fragile.** Modern pip does not support `setup.py install` lifecycle hooks; a wheel that downloads its own binary post-install relies on deprecated behaviour.
- **Pre-built platform wheels are the established pattern.** Tools like `ruff` and `uv` use the same approach: CI compiles the binary, packages it into a wheel, publishes to PyPI. `pip` selects the correct wheel for the host platform automatically.

## Shape of the wheel

- Build backend: `maturin` (root `pyproject.toml`; `python-source = "python"`, `manifest-path = "bunsen-core/Cargo.toml"`).
- The compiled `bunsen-core` binary lands at `bunsen/bin/bunsen-core` inside the wheel. The Python library locates it via `Path(__file__).parent / "bin" / "bunsen-core"`, with `BUNSEN_CORE_BIN` as a developer override.
- Wheel version is read from `bunsen-core/Cargo.toml` — single source of truth.

## Target platforms

`linux/x86_64` and `linux/aarch64` only. Firecracker requires Linux + KVM (ADR 0001); macOS is a dev-only environment reached via a Linux VM. No Windows target.

## Build matrix

Both targets are cross-compiled on x86_64 GitHub Actions runners using `PyO3/maturin-action` with `cross`. Native aarch64 runners are not required; `bunsen-core`'s dependencies (`nix`, `reqwest`/`rustls`, `tokio`) cross-compile without issue.

## Release workflow

A push of a `v*` tag triggers the CI build matrix. Both wheels are published to PyPI in a single release job using `pypa/gh-action-pypi-publish` with OIDC Trusted Publishers — no API tokens stored in repository secrets.

## Kernel distribution

The vmlinux is not bundled in the wheel. It is fetched lazily on first `run()` by `bunsen-core` (see ADR 0008). The wheel therefore stays small and the same lazy-fetch path serves both installed and development builds.

## Considered Options

- **Bundle vmlinux in the wheel.** Fits within PyPI's 100 MB per-file limit but adds ~50 MB to every install regardless of whether the user will ever run on that architecture. Rejected — the kernel is already fetched lazily and bundling it provides offline support only for the kernel, not for the OCI rootfs (which is always fetched at first run).
- **Separate `bunsen-kernel` PyPI package.** Cleaner separation of concerns but adds a second publishing workflow and a second wheel build matrix for a file that is already cached and versioned independently. Rejected.
- **Post-install download hook.** The wheel downloads `bunsen-core` from GitHub Releases after install. Simple to build but relies on deprecated `setup.py install` lifecycle behaviour. Rejected.
- **Compile on install (sdist only).** Requires Rust on every user's machine. Rejected as a primary path; an sdist can be published alongside the wheels as a source fallback for unsupported platforms.
