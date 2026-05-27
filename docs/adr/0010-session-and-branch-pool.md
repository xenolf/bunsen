# Session and Branch Pool: cross-Run sharing without touching the host repo

A Session is the bounded orchestration context over a host repo, with an explicit open/close lifecycle. Each Session owns a Branch Pool — a host-side git store, separate from the user's host repo — into which agent-produced refs are fetched at Run end and from which downstream Runs source their starting state. The host repo is mirrored into the Pool at open time, never touched again until the user explicitly closes the Session with a manifest of `(pool_ref, host_ref)` pairs to sync back. The Workspace is strict commit-shaped: the only data channel between a Sandbox and the host is `git fetch`, and the host keeps no workspace directory after Run end.

## Why

The motivating scenario: a User Script orchestrates N Coding-Agent Runs over a set of issues with a dependency graph (some unblocked, some downstream). The unblocked Runs work in parallel; the downstream Runs need the *reconciled* output of the unblocked Runs as their starting point. The host repo should not see intermediate state — only the final result, and only when the user asks.

That requires three things bunsen didn't have before:

- A place for agent-produced refs to live between the Run that creates them and the Run that consumes them, without bleeding into the host repo. → **Branch Pool**.
- A bounded context that owns the Pool and defines when host-repo writes are permitted. → **Session**.
- A guarantee that what flows out of a Run is what the agent committed, not whatever happens to be on disk in the ext4. Otherwise "reconcile branches" is undefined when uncommitted scratch files differ from the committed tree. → **Workspace is commit-shaped; Pool is the only post-Run source of truth**.

## Considered Options

- **Push agent commits directly into the host repo as `bunsen/run-<id>` branches** (the v1 status quo `worktree:` strategy). Simplest, but the user's `git branch -a` fills with bunsen state immediately, and "I don't want this Run's branch in my repo yet" is awkward. Rejected: leaks intermediate state into the host repo.
- **Run-to-Run reference via run-dir .git directories** (each downstream Run clones from `runs/<upstream>/workspace/.git`). No new shared store, but pruning a Run dir breaks downstream materialisations, and the dependency graph between Run dirs is fragile under cleanup. Rejected: run dirs are a log, not a store.
- **Per-host-repo persistent Pool, no Session** (an always-on Pool with a separate "sync to host" verb). Considered; lacks the bounded lifecycle that makes "host repo not touched in this window" a contractable invariant, and accumulates audit refs forever with no GC story.
- **Session + Pool, with a non-git tree-copy fallback for non-Workspace inputs.** Rejected: reintroduces the "the agent did X but it's not in any commit" ambiguity that the Pool model exists to kill.

## Consequences

- The materialiser sources all Runs from the Pool, not from the host repo directly. The host repo is `git fetch`-mirrored into the Pool at Session open under `host/<ref>` names. The set of mirrored refs is declared at open time (default: the host's default branch). Refs not mirrored fail loudly when referenced by a Run.
- The Workspace is no longer extracted to `runs/<id>/workspace/` on the host. At Run end, the ext4 image is mounted read-only and `git fetch <mount>/.git HEAD:<refs>` writes into the Pool. Inspection of files happens via `git worktree add` from a Pool ref, not by browsing a host directory. `RunDir::workspace_path()` is removed.
- Branching Strategy becomes a typed sum: `enum BranchingStrategy { None, PoolClone { base: String, import: Vec<String> } }`. The legacy `fresh-clone:<ref>`, `worktree:<ref>`, and `copy-worktree` string variants are removed. `fresh-clone:main` becomes `PoolClone { base: "host/main", import: [] }`; the other two have no equivalent under the new model and are gone.
- Sessions are mandatory. There is no Run outside a Session. A Python context manager (`with bunsen.open_session(...)`) covers the one-off case; close is always explicit and never implicit at scope exit — a User Script that exits the `with` block without calling `close()` leaves the Session open and detached.
- Sessions are persistent: stored on disk under `~/.local/share/bunsen/sessions/<ulid>/`, identified by ULID, with optional user labels for human listing. Run dirs nest as `sessions/<id>/runs/<run-id>/`. Discarding a Session is `rm -rf` of one directory; no orphan run dirs exist by construction.
- Close takes an explicit manifest of `(pool_ref, host_ref)` pairs with a default of fast-forward-only. `force: true` opts a pair into non-FF push. Validation is all-or-nothing: any pair that would lose history aborts the whole close before any push is attempted. A failed close leaves the Session in `failed_to_close`, which permits new Runs and close retries.
- Audit refs (`runs/<run-id>`) are written for every Run that produces commits and are *never* pushed to the host repo by close. They are the in-Pool provenance trail and the basis on which user-named `output_branch` refs are layered.
- Reconciliation is a Run, not a bunsen primitive. A `PoolClone { base, import }` strategy gives the agent inside the guest all the refs it needs to `git merge` and resolve conflicts. Bunsen itself never produces commits.
- `host_repo_path` moves out of `RunSpec` into the Session. The host-repo URL is set once, at open. RunSpec's `branching_strategy` becomes the typed `BranchingStrategy` (non-optional, with a `None` variant).

This decision pairs with [ADR-0011](0011-hardened-git-fetch-from-sandbox.md), which covers the security posture of the Pool fetch itself.
