# ADR 0126: Native trusted-time lifecycle-v2 milestone-two owner foundation

- Status: Implemented locally for Wave 7; final full regression, independent
  security review, promotion, and remote CI verification remain pending, and
  this decision grants no runtime, deployment, lifecycle-root, Docker-effect,
  recovery-effect, or stop authority
- Date: 2026-08-28
- Implements the owner boundary in milestone two of:
  [ADR 0121](0121-trusted-time-graceful-stop-lifecycle-v2-implementation-resolution.md)
- Follows the completed injected milestone-one record:
  [ADR 0125](0125-complete-injected-trusted-time-lifecycle-v2-milestone-one.md)

## Context

ADR 0121 freezes the lifecycle-v2 protocol and divides implementation into four
non-effecting milestones. ADR 0125 completes milestone one: all contracts,
injected storage, injected transport and Docker seams, exact lifecycle
sequencing, and classification-only recovery exist without a production caller.
Milestone two must add native endpoint, signer, fork, key, mount, and launch
owners while preserving that zero-caller boundary.

Several supply-chain and executable-layout choices were intentionally not fixed
by ADR 0121. In particular, it does not select a native Ed25519 primitive, name
the separately constrained host/supervisor/recovery executables, define the
fixed provisioner boundary, freeze a seccomp representation, name the retained
authority-chain files, or define a test seam for literal production paths.
Those choices affect recovery isolation and private-key custody and must be
reviewed before parallel native implementation begins.

This ADR fills only those milestone-two implementation choices. ADR 0121
remains normative for every transport, key, identity, deadline, lifecycle, and
recovery contract.

## Decision

### Keep Wave 7 inside milestone two

Wave 7 may add only:

- a native pre-Python fork guard and fixed owner table;
- native role-constrained signer owners;
- native Linux pathname Unix-seqpacket endpoint owners;
- native key, socket, mount, process, and peer admission primitives;
- encrypted-credential provisioners that write only to the exact preopened
  role-tmpfs inode;
- separately compiled host, supervisor, recovery, and provisioner profiles;
- source-only systemd mount/service units and canonical seccomp manifests; and
- adversarial, packaging, reproducibility, and static-isolation evidence.

Wave 7 must not add or inspect a default or real lifecycle root, compose a real
Docker transport or effect, add a production lifecycle/controller caller,
project the new resources through Compose, install or activate a systemd unit,
create a deployment route, or enable recovery or stop effects. It must not edit
the behavior of `make trusted-time-stop`, which remains the exact two-line,
no-prerequisite exit-2 hard close required by ADR 0121.

Every Wave 7 build or admission record must state
`activation_authorized=false`. Candidate executables are packaging evidence,
not installed runtime owners.

### Vendor exactly Monocypher 4.0.3 for native Ed25519

The native signer vendors the unmodified Monocypher 4.0.3 release from
`https://github.com/LoupVaillant/Monocypher`, tag `4.0.3`, commit
`ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f`. Version 4.0.3 is required because
the upstream release fixes the compiler-introduced EdDSA/Ed25519 timing leak
affecting version 4.0.2 and earlier.

The official release archive is admitted only when its SHA-512 is exactly:

```text
40904ada5c7ee4f7741733e38b69a30a4b0561cbffba5ffe7c2dce16136d540251ec0d9056ff606510d3b5b708fb8a40db7e0870d4a0b2dc17ba2bfb880f8965
```

The repository retains exactly these unpatched upstream files below
`third_party/monocypher/4.0.3/`:

- `LICENCE.md`;
- `src/monocypher.c` and `src/monocypher.h`; and
- `src/optional/monocypher-ed25519.c` and
  `src/optional/monocypher-ed25519.h`.

`VENDORING.json` binds the upstream URL, tag, commit, release-archive SHA-512,
and each retained file's path, size, and SHA-256. The source headers and full
dual `BSD-2-Clause OR CC0-1.0` license remain intact and the license is included
with every candidate binary manifest.

The sources compile directly into each admitted native candidate. No
Monocypher shared library, OpenSSL/libsodium link, runtime lookup, `dlopen`, or
new dynamic dependency is allowed. Link-time optimization is forbidden. Hidden
visibility and final symbol audits must prove that no `crypto_*`, generic-sign,
raw-secret, or test-inspection symbol is exported.

First-party code may call only `crypto_ed25519_key_pair`,
`crypto_ed25519_sign`, `crypto_ed25519_check`, and `crypto_wipe`. A bootstrap
RFC 8032 vector-one self-test must pass before a signer owner can become usable.
All three basic RFC 8032 Ed25519 vectors, cross-verification with the existing
compiled public verifier, tamper vectors, and exact compiler/assembly evidence
for the 4.0.3 conditional-copy mitigation are pre-promotion gates.

### Use separately compiled fixed role profiles

The exact candidate executables are:

| Role | Exact executable |
| --- | --- |
| Host | `/opt/autoquant/trusted-time-graceful-stop-v2-host/bin/autoquant-trusted-time-graceful-stop-v2-host` |
| Supervisor | `/opt/autoquant/trusted-time-graceful-stop-v2-supervisor/bin/autoquant-trusted-time-graceful-stop-v2-supervisor` |
| Recovery | `/opt/autoquant/trusted-time-graceful-stop-v2-recovery/bin/autoquant-trusted-time-graceful-stop-v2-recovery` |
| Host provisioner | `/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/autoquant-trusted-time-graceful-stop-v2-host-provision` |
| Supervisor provisioner | `/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/autoquant-trusted-time-graceful-stop-v2-supervisor-provision` |
| Recovery provisioner | `/opt/autoquant/trusted-time-graceful-stop-v2-provision/bin/autoquant-trusted-time-graceful-stop-v2-recovery-provision` |

Each executable requires exactly `argc == 1`. Role selection by argv,
environment, basename dispatch, symlink, `%i`, or a generic subcommand is
forbidden. The current multi-target trusted-time launcher is not widened.
One provisioner source is compiled three times under mutually exclusive
compile-time role macros; it does not produce a generic fourth provisioner.

The host profile contains only the fork guard, host signer, seqpacket
connector, host resource admission, owner cleanup, and host seccomp capability.
The supervisor profile contains the corresponding supervisor signer, listener,
resource admission, cleanup, and supervisor seccomp capability. The recovery
profile contains only the fork guard, recovery-classification signer, cleanup,
and recovery seccomp capability. Its separately emitted exact minimal bootstrap
standard-library tree contains only the required encoding modules and Python
license, and its one immutable inert entry root omits host and supervisor
wrappers, endpoint code, Docker domain/adapters, and subprocess facilities. It
has no dynamic-extension load path. Libpython built-ins are inventoried rather
than claimed absent; they remain unreachable from the no-input inert entry, and
seccomp blocks effects. Arbitrary-Python-compromise safety and full operational
import/dependency composition remain milestone-three activation blockers.

The recovery preprocessed source, link map, import manifest, undefined-symbol
table, and binary strings must prove absence of normal key names and paths, the
transport path and socket, Docker socket/API strings, container/network/volume
methods, and host/supervisor provisioner names. They also forbid socket,
connect/bind/listen/accept/send/receive, process-creation, exec, dynamic-loader,
and shell APIs. The recovery executable has no Python dynamic-extension search
path and cannot load an omitted capability after launch.

### Install the fork guard before Python

`native/trusted_time_v2_fork_guard.c` owns one fixed table of 128 descriptor
slots. Initialization occurs before `Py_InitializeFromConfig` in every fixed
role launcher and proves the required atomics are lock-free before registering
`pthread_atfork`.

Each slot is atomic and contains either `-1` or one owned descriptor. A table
generation changes on every registration and removal. The at-fork prepare
handler snapshots that generation without a lock. The parent handler preserves
its epoch only when the generation is unchanged; otherwise it poisons the
process. The child handler performs only async-signal-safe work: it increments
the native epoch, poisons the process, atomically extracts and closes every
table descriptor, and returns. It acquires no mutex, allocates no memory, and
calls no Python.

Every v2 owner captures the origin PID, exact native thread, interpreter
identity, native epoch, and table generation. It validates them before any
Python/native lock or owner dereference. A later Python at-fork child hook may
replace locks and empty registries, but may not touch inherited owners or clear
the native poison. The existing native descriptor owner must adopt this guard
for lifecycle-v2 descriptors rather than retaining an independent dynamic
at-fork authority.

### Keep signer methods role- and message-specific

The signer stores the complete 64-byte Monocypher secret key in a dedicated
native mapping. It requires `mlock` and Linux
`MADV_DONTDUMP|MADV_WIPEONFORK`, derives the public key, compares it to the
authenticated manifest key, and exact-inode-unlinks the loaded 32-byte seed
before exposing any signing method. A failed lock, advice, metadata check,
public-key match, unlink, owner check, or bootstrap self-test burns the owner.

The only readable secret-derived value is the 32-byte public key. Host methods
sign only host hello, host channel confirmation, and clean-stop request
domains. Supervisor methods sign only supervisor hello, clean-stop result,
clean-stop error, and supervisor cleanup-commitment domains. Recovery signs
only the recovery-classification domain. There is no generic `sign`, role
argument, raw key getter, secret export, pickle/copy path, or alternate domain.

Close is idempotent. Every ordinary, failed, asynchronous-cleanup, terminal,
recovery, and parent-invalid path calls the admitted explicit wipe before
`munlock` and unmap. Fork-child confidentiality relies on the already-required
kernel `MADV_WIPEONFORK`; the async child handler closes descriptors and never
attempts a non-async-safe userspace wipe.

### Expose closed endpoint state machines

The host native surface is exactly connector creation, host-hello send,
supervisor-hello receive, host-confirmation send, request send, one terminal
result-or-error receive, and close. The supervisor surface is exactly listener
creation, one accept, host-hello receive, supervisor-hello send,
host-confirmation receive, request receive, one terminal result-or-error send,
and close. No generic send, receive, socket, path, role, counter, or reconnect
method is exposed.

The owners enforce ADR 0121's direction counters internally. Each receive uses
one `recvmsg` into the fixed 262,145-byte detection buffer, accepts at most
262,144 bytes, and rejects truncation, control truncation, ancillary data,
continuation, extra packets, and post-terminal traffic. Creation binds the
five-second handshake deadline; each operation uses a non-extensible two-second
deadline under `CLOCK_BOOTTIME`, and equality is expired.

Production profiles compile the literal socket and resource paths from ADR
0121. Tests do not introduce a runtime path override. A separately compiled
test profile accepts only preopened directory/key descriptors and socket-pair
owners, so production path strings and no-follow admission remain literal while
faults can be exercised without root or host mounts. No test constructor is
linked into a role candidate.

Linux resource admission stable-reads mountinfo, directory/socket Stat9,
`SO_PEERCRED`, and the required `/proc` identities, binds the captured
device/inode and mount identity to the owner, and revalidates them through
close. It rejects every wrong tmpfs option, owner/mode, symlink, link count,
entry, projection, PID/UID/GID, inode, namespace, process, container/image, or
identity drift described by ADR 0121. macOS compiles only portable fork,
signer-crypto, and test seams; operational mount, peer, and endpoint admission
reports unsupported.

### Authenticate generation inside argument-free provisioners

No generation, role, path, output, key, or extra value crosses argv or the
environment. Each fixed provisioner stable-loads the reviewed transport-root
public key, the fixed `selection.json`, and the complete content-addressed
authority chain using the existing canonical Ed25519 authority rules. It mints
one opaque PID/thread/interpreter/fork-bound, one-use selected-generation seal.
The host and supervisor seals derive only from the authenticated selected
generation. The recovery seal derives from an injected-root generation and
requires its pinned manifest digest to equal `recovery_manifest_sha256`; Wave 7
adds no real-root reader or route to that seam.

The native consumer accepts only generations `1..99999999`, formats exactly
eight decimal digits in a fixed buffer, and uses compile-time role literals to
construct the sole encrypted-blob and tmpfs-target paths. The child argv is
exactly the ADR-0121 command:

```text
/usr/bin/systemd-creds decrypt --name=<literal-role-name> <exact-blob> -
```

Before process creation, the parent consumes the selected-generation seal,
copies only its nonsecret expected public key and generation into fixed native
storage, closes every authority-chain descriptor, and proves the fork-guard
owner table empty. It then exclusively creates the exact no-follow target,
sets the fixed role ownership/mode, and duplicates that same inode to child FD
one. FD zero is fixed read-only `/dev/null`; FDs zero and one are deliberately
outside the owner table, and every child descriptor other than zero and one is
closed. The decrypted bytes can therefore reach only the preopened inode.

The parent stable-opens the root-owned, non-writable literal
`/usr/bin/systemd-creds`, verifies the executable identity and SHA-256 pinned by
the candidate/deployment manifest, and executes that same descriptor with
`execveat(..., AT_EMPTY_PATH)`. A fixed native state machine permits exactly one
such child; seccomp alone is not treated as executable-identity or child-count
proof. The at-fork child poison is expected because the child immediately
executes and retains only FDs zero and one. The parent requires zero exit,
exactly 32 stable bytes, the same single-link target inode/metadata, and the
authenticated manifest public key, then wipes every derivation buffer. Failure
unlinks only that exact inode.

### Freeze authority-chain names and metadata

The authority directory remains exactly
`/opt/autoquant/trusted-time/authorities/graceful-stop-v2`. Manifest files are:

```text
transport-authority-manifest-g<generation:08d>-<manifest_sha256>.json
```

Retained selection records are:

```text
transport-authority-selection-s<selection_sequence:08d>-<selection_sha256>.json
```

`selection.json` is a byte-identical ordinary file for the retained selection
head, never a symlink or mutable indirection. The root key, manifests,
selections, and head are root-owned, single-link, non-writable regular files in
one root-owned non-writable no-symlink directory. Digests are ordinary SHA-256
of complete canonical signed bytes, matching the milestone-one codecs.

### Retain source-only systemd topology

Source units live below `infra/trusted-time/graceful-stop-v2/systemd/`. The four
mount-unit basenames are exactly:

- `run-autoquant-trusted\x2dtime-graceful\x2dstop\x2dv2-transport.mount`;
- `run-autoquant-trusted\x2dtime-graceful\x2dstop\x2dv2-host\x2dsecrets.mount`;
- `run-autoquant-trusted\x2dtime-graceful\x2dstop\x2dv2-supervisor\x2dsecrets.mount`;
  and
- `run-autoquant-trusted\x2dtime-graceful\x2dstop\x2dv2-recovery\x2dsecrets.mount`.

They use ADR 0121's literal tmpfs options, owners, and modes for transport,
host secrets, supervisor secrets, and recovery secrets. The three endpoint
service basenames are exactly
`autoquant-trusted-time-graceful-stop-v2-host.service`,
`autoquant-trusted-time-graceful-stop-v2-supervisor.service`, and
`autoquant-trusted-time-graceful-stop-v2-recovery.service`. The three provision
service and credential names remain exactly those frozen by ADR 0121.

Secret mounts precede and are required by their role provisioner. The
transport mount precedes host and supervisor endpoints. Endpoint units require
their provisioner and required mounts. Recovery conflicts with every normal
owner and the transport mount; normal profiles require the recovery mount to be
absent.

Every Wave 7 unit deliberately has no `[Install]`, `WantedBy`, installer,
enable/start command, daemon-reload path, or Compose projection. The units are
parse-tested source evidence only.

### Pin native seccomp manifests

Canonical manifests live below
`infra/trusted-time/graceful-stop-v2/seccomp/` as `host.json`,
`supervisor.json`, `recovery.json`, and `provisioner.json`. They bind Linux
architecture, ordered syscall policy, generated BPF SHA-256, source SHA-256,
activation phase, and exact role capability tuple.

Host, supervisor, and recovery profiles install the native at-fork guard first,
then set `PR_SET_NO_NEW_PRIVS` and install a TSYNC seccomp filter before Python
initialization or owner exposure. Architecture mismatch kills the process.
`fork`, `vfork`, `clone`, `clone3`, `execve`, `execveat`, `unshare`, and `setns`
return `EPERM`; the recovery profile additionally denies all socket creation,
connection, listener, send, and receive syscalls.

Every role filter is generated at build time, compiled into its binary, and
byte-bound to the corresponding canonical manifest; runtime JSON parsing does
not select or construct BPF. The reviewed allow surface includes the exact
CPython initialization and fixed-import syscalls required before owner
exposure.

The provisioner is a distinct two-phase profile. Its compiled pre-child filter
denies networking and permits the process syscalls required for its one native,
descriptor-pinned `systemd-creds` child. Immediately after that child is
reaped, it stacks a stricter compiled filter denying every later process
creation and exec. The native state machine, stable executable identity, and
`execveat` descriptor—not classic seccomp argument inspection—prove the exact
child and count. Its manifest truthfully records `process_creation_denied=false`
for the pre-child phase, `one_pinned_systemd_creds_child=true`, and
`process_creation_denied=true` for the post-child phase. It must not claim the
normal role seccomp profile.

On macOS, seccomp activation deterministically reports unsupported. Linux CI
builds and exercises every role candidate and seccomp vector; the existing
macOS Python 3.12/3.13 matrix continues to compile and exercise only the shared
portable native code.

### Integrate in one controlled order

Implementation order is:

1. vendor and attest Monocypher and add RFC 8032 tests;
2. land the fixed-table fork guard ABI and migrate lifecycle-v2 descriptor
   ownership to it;
3. implement signer and endpoint/resource lanes in parallel;
4. implement the three argument-free provisioners and source-only units;
5. build the separate fixed profiles and static recovery exclusions;
6. reconcile packaging, native dependency audits, source/import manifests,
   architecture policy, and CI; and
7. run focused fault matrices, both native packaging versions on Linux and
   macOS, the complete backend/frontend/container regression, and an
   independent security review.

Shared launcher/build/install/policy/CI files have one integration owner. Lane
branches must not edit them independently.

## Consequences

Milestone-two implementation now has an exact cryptographic supply chain and
executable topology on the local integration branch. Recovery isolation is
structural: it is a different binary, minimal bootstrap standard-library tree,
and inert import root, not a runtime role flag. Raw private bytes remain native
and tmpfs-only. Provisioning does not accept caller-selected generations or
write plaintext through a pipe, terminal, journal, or ordinary filesystem.
Fork-child descriptor invalidation precedes Python and seccomp prevents process
creation after owner activation.

The cost is six role binaries, four seccomp manifests, source-only systemd
topology, a larger vendored native review surface, and Linux-specific
qualification. Monocypher 4.0.3 is a recent timing-hardening release whose
earlier Cure53 review predates that fix, so exact-compiler constant-time evidence
remains mandatory.

The local implementation produces six reproducible candidate executables, four
canonical x86_64 seccomp manifests, and source-only systemd units. The
candidates and units are not installed; candidate builders and native sources
are retained in the source distribution only and excluded from wheels; the
role import trees are immutable and inert; and every candidate record states
`activation_authorized=false`. Final full regression, independent security
review, promotion, and remote CI verification remain pending.

No operational behavior changes merely because this milestone is implemented.
There is still no production/default real lifecycle root, real Docker
transport/effect, production controller/runtime caller, Compose projection,
installation or activation, deployment, recovery effect, or stop authority.
Milestone three still owns isolated injected real-root/Docker and operational
import/dependency composition; signed socket/process-epoch evidence binding boot
UUID, executable/import hashes, nonce, and immutable image; bounded
`/proc/<pid>/fd` and `/proc/net/unix` pre/post channel-closure proof; and
arbitrary-Python-compromise safety. Milestone four still owns immutable
production release, deployment, drills, activation, and every stop-authority
change. `make trusted-time-stop` remains the exact exit-2 hard close, and the
trader remains `not_ready`.
