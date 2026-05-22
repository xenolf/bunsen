# Firecracker as v1 Sandbox Provider

We picked Firecracker over Bubblewrap as the v1 Sandbox Provider because the threat model includes adversarial agent code attempting to escape the Sandbox, and a microVM kernel boundary is materially harder to cross than a namespace + seccomp boundary. The Sandbox Provider is pluggable so Bubblewrap (and others) can be added later as a "fast iteration" alternative when isolation requirements are weaker.

## Considered Options

- **Bubblewrap** — Linux namespaces + seccomp. Near-native performance, sandbox starts in milliseconds. Rejected for v1 because the kernel itself is the escape surface; a hostile agent has the entire Linux syscall surface to probe.
- **Firecracker** — KVM microVM with its own kernel. ~125ms boot, virtio-fs for code mounting, TAP device for networking. Heavier than bwrap but the isolation boundary is qualitatively different.

## Consequences

The Run primitive must be Sandbox Provider-agnostic from day one — provider-specific concerns (vsock, virtio-fs, TAP devices for Firecracker; bind mounts and netns for Bubblewrap) live behind the Sandbox Provider abstraction, not in the Run.

Firecracker is Linux + KVM only. Mac developers run crucible inside a Linux VM. This is a known cost.
