# macOS

## TL;DR

**v1 has no native macOS path.** Crucible's sandbox provider is Firecracker, which needs the Linux KVM API. macOS does not expose KVM, and Apple's Hypervisor.framework is not a drop-in substitute. The only supported workflow on a Mac is to SSH to a remote Linux box with nested virtualization and develop there.

## Why no Apple Silicon path

- Firecracker is x86_64 + aarch64 Linux only. The Hypervisor.framework API is fundamentally different — porting Firecracker would be its own project.
- Some primitives crucible depends on (nftables, ext4 rootfs images, journalctl, /sbin/init bring-up via a custom guest kernel) are Linux-specific.
- Cross-architecture (Apple Silicon host, x86_64 guest) would require QEMU/TCG emulation. The performance is too poor to be useful for agent work.

Intel Mac users *can* in theory enable nested KVM inside a Linux VM (Lima, Multipass, UTM) and run crucible there, but no recipe is shipped and the path is not exercised in CI. Treat it as unsupported.

## Recommended workflow: remote Linux box

Most of the team uses one of these:

- **Hetzner Cloud** — `CCX13` (dedicated vCPU, 8 GB RAM, KVM-on-AMD) is enough for a Run and costs roughly €13/month.
- **AWS EC2** — `c5.metal` or `c5n.metal` (bare metal — needed because regular instance types disable nested virt). Pricey but available everywhere.
- **GCP** — any N2/C2 instance with `--enable-nested-virtualization` set at creation time.

Pick whatever your team already has provisioning for. The instructions below are provider-agnostic.

### One-page setup

On the remote box, as a sudoer:

```sh
# 1. Verify KVM is actually accessible.
ls -l /dev/kvm
# If missing: the host doesn't have nested virt enabled. Stop and fix that first.

# 2. Add yourself to the kvm group so Firecracker can open /dev/kvm without sudo.
sudo usermod -aG kvm "$USER"
# Log out and back in so the new group sticks.

# 3. System packages.
sudo apt-get update
sudo apt-get install -y \
    build-essential pkg-config libssl-dev \
    nftables iptables iproute2 \
    docker.io e2fsprogs genext2fs \
    python3-venv git curl
sudo usermod -aG docker "$USER"

# 4. Firecracker.
FC_VER=v1.15.0
curl -fsSL -o /tmp/fc.tgz \
    "https://github.com/firecracker-microvm/firecracker/releases/download/${FC_VER}/firecracker-${FC_VER}-x86_64.tgz"
tar -xzf /tmp/fc.tgz -C /tmp
sudo install -m 0755 "/tmp/release-${FC_VER}-x86_64/firecracker-${FC_VER}-x86_64" /usr/local/bin/firecracker

# 5. Rust.
curl -fsSL https://sh.rustup.rs | sh -s -- -y
. "$HOME/.cargo/env"
rustup target add x86_64-unknown-linux-musl

# 6. Clone and build crucible (see README.md).
git clone https://github.com/<you>/crucible.git
cd crucible
cargo build --release
cargo build --release -p crucible-init --target x86_64-unknown-linux-musl
./kernel/fetch-vmlinux.sh
./adapters/_smoke-test/build-rootfs.sh
python3 -m venv .venv && source .venv/bin/activate
pip install -e './python[dev]'

# 7. Smoke-test.
pytest -q python/tests

# 8. Acceptance suite (Linux + KVM gated).
CRUCIBLE_KERNEL=~/.cache/crucible/kernel/vmlinux \
CRUCIBLE_ROOTFS=$(pwd)/target/smoke-rootfs.ext4 \
pytest -v python/tests/test_egress_acceptance.py
```

If the acceptance suite reports `failed to bind DNS listener on 169.254.x.1:53 (EACCES)`, give the binary the privileged-port capability:

```sh
sudo setcap 'cap_net_bind_service,cap_net_admin=+ep' target/release/crucible-core
```

(`cap_net_admin` is what lets crucible drive nftables / TAP devices unprivileged.)

### Working from a Mac

Either:

- **SSH + a remote IDE.** VS Code Remote-SSH, JetBrains Gateway, and Cursor all work — crucible builds with `cargo` and edits like any other Rust + Python project. Run `cargo test` and `pytest` on the remote side.
- **rsync + `ssh -t`.** If you prefer a local editor, sync your tree with `rsync -avz --exclude target ./ user@host:crucible/` and invoke `cargo`/`pytest` over SSH.

The Python library and the host binary live on the same machine — there is no "client/server" split. Your User Script runs on the Linux box.

## What does work on macOS

- `cargo build`, `cargo test` (host-only paths skip the Linux-gated tests).
- `pytest python/tests/test_subprocess_driver.py` and other Linux-unaware unit tests.
- Editing the source, reading the docs, writing tests, reviewing PRs.

What *won't* work locally: anything that boots a VM, materialises a rootfs, or exercises `EgressDenied`. Those all require `/dev/kvm`.
