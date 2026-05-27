# Hardened git fetch from the Sandbox's .git

The host-side `git fetch` that reads commits out of a Run's Sandbox runs with explicit hardening flags, with the ext4 image mounted read-only (`nosuid,nodev,noexec`), and as the User Script's user — not root. The minimum privileged surface is the mount itself; everything after it is deprivileged.

## Why

ADR-0001 established that the threat model includes adversarial agent code attempting to escape the Sandbox. The Coding Agent has full RW access to the Workspace's `.git` directory inside the guest. At Run end, bunsen's host-side process fetches refs out of that `.git` to populate the Branch Pool (see [ADR-0010](0010-session-and-branch-pool.md)). That fetch is reading attacker-controlled bytes through git's local-path code path — the same code path that has historically produced CVEs around hooks, submodules, hardlinks, fsmonitor, and credential helpers.

Trusting git's own hardening *and nothing else* is incoherent with the rest of the architecture: the project spent a microVM kernel boundary's worth of capital on resisting an adversarial agent, then would ask git to defend the data channel out by itself. ADR-0005 made the analogous argument for egress (L3 + L7, not L7 alone). The same logic applies here.

## What "hardened" means concretely

The host-side fetch process runs with:

- `GIT_CONFIG_NOSYSTEM=1` — ignore `/etc/gitconfig`.
- `GIT_CONFIG_GLOBAL=/dev/null` — ignore the user's `~/.gitconfig`.
- `-c core.hooksPath=/dev/null` — no hooks fire.
- `-c protocol.file.allow=user` — allow `file://` for fetch; the default in modern git but pinned explicitly.
- `-c credential.helper=` — no credential helper invocations.
- An *explicit* refspec: `HEAD:runs/<run-id>` (and, optionally, `HEAD:<output_branch>` when the RunSpec declared one). Never `+refs/*:refs/*` — that would let an agent inject refs into our namespace.
- `--no-recurse-submodules`.

The ext4 holding the agent's `.git` is mounted read-only with `nosuid,nodev,noexec` for the duration of the fetch and unmounted immediately after. The privileged shim that performs `losetup` + `mount` runs as root (or via a capability-bounded helper); the `git fetch` itself runs as the User Script's user.

## Considered Options

- **Trust git's own hardening** (just `git fetch <path>` as the User Script's user, ext4 mounted ro). Rejected: incoherent with ADR-0001's threat model. A single CVE in git's local-fetch code path puts the host process at the agent's mercy.
- **Hardened fetch** (chosen). The flag set above is bog-standard "untrusted source" posture; every flag has a specific attack it neutralises. Cost: half a dozen `-c` flags, two env vars, and the discipline to keep the fetch isolated in one function so the posture cannot drift.
- **Two-stage fetch with quarantine ref + validation.** Fetch into `quarantine/<run-id>`, validate the tip (object types, ref-name shape, optional size budget), then atomically rename to `runs/<run-id>` and any user-named ref. Better defence-in-depth, more code. Not necessary for a local dev tool; the fetch is isolated in one function so this is a clean future upgrade, not a rewrite.

## Consequences

- The Workspace extraction code in `firecracker.rs` is reshaped: where it previously did `losetup` + `mount` + `cp -a`, it now does `losetup` + `mount` (read-only) + `git fetch` (hardened, deprivileged) + `umount`. No tree copy; the original `cp -a` site is removed entirely along with the "phantom deleted files" footgun it had.
- The agent's native history files (the [[conversation-history]] escape hatch, e.g. `.claude/`) are still extracted via a narrow file copy of known subpaths — not `cp -a` over the whole tree. Symlinks in that subtree should not be followed.
- A future move to a quarantine-ref two-stage fetch is a refactor of the fetch helper, not a redesign. The Pool already supports arbitrary ref names; adding a `quarantine/*` namespace and a validator is additive.
- Any future change to the Pool fetch path (supporting multiple output refs in a single Run, switching from `fetch` to `push`, etc.) must re-evaluate the flag set here. The flag set is the API contract, not the invocation.
