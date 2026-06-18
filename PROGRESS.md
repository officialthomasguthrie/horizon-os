# Horizon build progress

The design lives in `docs/`. This file tracks what actually exists in code.

Repo: https://github.com/officialthomasguthrie/horizon-os

## Phases

- Phase 0  Proof of life: bootable encrypted base on a Key, boots on x86-64 UEFI, persistent state
- Phase 1  Lifestream: content-addressed encrypted state store, generations, time travel
- Phase 2  Weave + Glass: capability broker, Cells, audit log, transparency
- Phase 3  Shell + compositor (Wayland, Smithay/iced)
- Phase 4  Aura: local model runtime, voice, semantic search, capability tools
- Phase 5  Constellation + Reconstitution: P2P sync, Shamir recovery
- Phase 6  Website + installer (Tauri)

## Done

- Design docs (docs/00-09, README, SUMMARY)
- Workspace scaffold (Cargo workspace, toolchain, license, editorconfig)
- Phase 1 lifestream crate: FastCDC chunker, encrypted content-addressed store
  (XChaCha20-Poly1305 with keyed BLAKE3 addressing), generations, history,
  time-travel restore, mark-and-sweep gc. 8 integration tests passing.
- horizon CLI: lifestream init / snapshot / log / restore / gc / refs / stat,
  with Argon2id passphrase key derivation.
- CI: fmt, clippy (-D warnings), test on push and PR.
- Phase 2 weave crate: object-capability broker over the Lifestream. Unforgeable
  capability handles scoped to a resource (file/net/device/service) and rights
  (r/w/x); grants are time- and use-limited and revocable; a request policy
  (allow/deny/rules) decides unsolicited asks. The audit log is an append-only,
  hash-chained sequence of entries stored as Lifestream Trees, so it is
  tamper-evident, gc-safe (reachable from one ref), and replayed on open to
  rebuild broker state. 11 tests passing.
- horizon weave CLI: grant / revoke / use / grants / audit / verify, plus a
  scripted `weave demo` that walks the full grant-use-deny-revoke lifecycle and
  prints the resulting audit log.
- Phase 5 constellation crate: object sync between two Lifestream stores of one
  identity. A Transport trait abstracts a peer; sync diffs the two id sets and
  ships only the sealed records the other side lacks (content addressing makes
  shared history free), then carries refs forward fast-forward-only, reporting
  divergence rather than clobbering it. Records cross as ciphertext and the
  receiver verifies each against its own key before committing, so a wrong
  identity is refused, not corrupted. LocalTransport is the in-process transport;
  a QUIC+Noise network skin implements the same trait later. 8 tests passing.
- horizon sync CLI: `horizon sync <from> <to> [--both]`. Creates the destination
  as a replica of the source identity when absent, refuses a foreign one, and
  reports objects moved and refs set / advanced / diverged.
- Phase 5 reconstitution crate: Shamir k-of-n recovery of the identity master
  key over GF(2^8). split turns the key into n shares (any k rebuild it, any k-1
  reveal nothing); combine interpolates back and verifies the result against a
  domain-separated tag carried on every share, so a corrupted or wrong-set share
  is caught instead of silently returning a wrong key. Shares are versioned,
  self-describing, and hex-portable. 11 tests passing, including every k-subset.
- horizon reconstitute CLI: `split <store> --k --n` cuts recovery shares from a
  store's master key; `open <store> --share ...` rebuilds the key from k shares
  and opens the store with no passphrase, decrypting HEAD to prove the key.
- Phase 5 constellation network transport (`net` feature, on by default): the
  QUIC + Noise skin behind the same Transport trait the in-process sync already
  runs on, so the sync algorithm in `sync()` does not change. quinn carries the
  bytes; a Noise NNpsk0 handshake, keyed by a PSK derived from the identity
  master, authenticates the peer and lays a second AEAD over a small request /
  response protocol (have, read_record, write_record, refs, get_ref, set_ref,
  parents). A wrong identity is refused at the handshake, before any object
  moves. QUIC's own TLS here is only the transport envelope (a throwaway
  self-signed cert, accept-any on the client); identity lives in the Noise layer
  alone, so terminating the TLS buys an attacker nothing. A record can be a
  64 KiB chunk plus sealing overhead, larger than one Noise message, so frames
  are length-prefixed and split into segments under the 65535-byte cap and
  reassembled on the far side. The trait stays blocking: the network side keeps
  its own tokio runtime and bridges each call with block_on, so neither the sync
  core nor the Lifestream (blocking file IO) is coloured async. Server serves one
  identity's store to peers; NetworkTransport is the dialing peer and also a
  Transport, so a network sync is `sync(remote, local)` or `sync(local, remote)`.
  4 loopback tests: push and pull with multi-segment records, cross-wire dedup
  and HEAD fast-forward, and wrong-identity refusal. Slim builds turn `net` off.
- horizon constellation CLI: `serve <store> [--listen host:port]` answers peers
  of the same identity until stopped; `sync <store> <peer> [--push] [--both]`
  dials a serving peer and runs the sync, default pull, --push to send, --both to
  converge the two stores.
- Concurrent-writer safety in the Lifestream store, so the Constellation server
  is safe to serve several peers at once. The store published every record
  through one fixed temp file (`<id>.tmp`) before renaming it into place; two
  peers pushing the same object id at once raced on that single temp file and
  could rename a half-written record or hit a vanished-temp rename error. Each
  write now uses a temp name unique to the writer (pid plus a process-global
  counter) before the atomic rename, so concurrent writers never collide; content
  addressing means whichever writer lands last leaves a valid record. The server
  already spawned a task per connection over one shared store, so this is what
  makes that safe. Tests: a lifestream concurrency test (8 threads racing
  overlapping object ids, confirmed to fail 12/12 without the fix) and a
  constellation test of 6 peers pushing into one server at once, one record large
  enough to be segmented on the wire.
- Phase 5 Constellation mDNS LAN discovery (`discovery` feature, on by default):
  find a peer of your identity on a LAN with no host:port typed in. A serving
  device advertises a DNS-SD service (`_horizon-cstl._udp`) carrying a short,
  non-secret fingerprint derived one-way from the identity master under its own
  domain separator, so it leaks neither the master nor the Lifestream/Noise keys.
  A peer browses, matches the fingerprint, and dials the resolved address. The
  fingerprint is only a rendezvous label; authentication is still the Noise
  NNpsk0 handshake, so broadcasting it grants nothing (a wrong identity that
  reads it still cannot connect). Beacon is RAII, dropping it withdraws the
  announcement. Unit tests cover the fingerprint (stable, identity-specific,
  distinct from the auth key); a live multicast roundtrip is #[ignore]d for CI
  (multicast is unreliable in the sandbox) and was verified on darwin, including
  an end-to-end CLI push to a discovered peer. CLI: `constellation serve`
  announces unless --no-announce, and `constellation sync <store> --discover`
  finds a peer instead of taking an address. Slim builds turn `discovery` off.
- Phase 5 Constellation rendezvous (`net` feature): find a peer beyond the LAN,
  where mDNS multicast does not reach. A rendezvous is a meeting point at a known
  address that every device of an identity can reach: a serving peer registers
  under its identity fingerprint (the same non-secret label mDNS broadcasts, now
  shared in one `label` module), and another peer of that identity looks the
  fingerprint up and gets the addresses to dial. The rendezvous holds no identity.
  It never sees the master, an object, or the Noise PSK, only a fingerprint and
  the IP a packet arrived from, so it can run on an untrusted shared host: the
  worst a hostile one can do is deny service or return a wrong address, and a
  wrong address simply fails the Noise handshake when dialed (so the dialer tries
  each returned address until one authenticates). The link to the rendezvous is
  QUIC with the same throwaway-cert envelope the sync uses; identity stays in the
  Noise layer between the two real peers alone. Registrations are leased presence
  (90s lease, 30s heartbeat) held only in memory, so a peer that stops serving
  ages out and a rendezvous restart just waits for everyone to re-register. The
  public address the rendezvous observes a peer at is recorded too, which is the
  input a future NAT hole punch needs. CLI: `constellation rendezvous` runs the
  meeting point; `serve --rendezvous <addr>` registers and heartbeats while
  serving; `sync --rendezvous <addr>` looks a peer up and dials it. Tests:
  registry lease/expiry/heartbeat/scoping and wire-codec units, plus a full
  loopback integration test (register, look up, dial, sync 200 KB of content)
  that runs in CI because the rendezvous is plain QUIC, not multicast; also
  verified end to end through the `horizon` binary against a running rendezvous.
- Phase 5 Constellation relay (`net` feature): reach a peer when no address
  either side learns is dialable, both behind NATs that refuse every inbound
  packet. A relay is a meeting point both peers reach with an outbound connection
  (which a NAT allows): a serving peer dials the relay and binds under its
  identity fingerprint (the same non-secret label mDNS and the rendezvous use,
  from the shared `label` module), and a dialing peer asks the relay to reach that
  fingerprint; the relay opens a fresh stream to the serving peer and splices the
  two together, forwarding opaque bytes. The Noise NNpsk0 handshake still runs end
  to end between the two real peers through the tunnel, so everything past it is
  ciphertext to the relay and a wrong identity is refused at the far peer exactly
  as on a direct link. The relay holds no identity (it sees only a fingerprint and
  the bytes it forwards) so it can run on an untrusted host: the worst a hostile
  one does is deny service or splice the wrong peers, who then fail each other's
  handshake. Because the sync runs over the same Noise channel either way, the
  relay path reuses the serve loop and the dialing transport unchanged; only how
  the stream is obtained differs. Presence is a live connection, not a lease: the
  relay keeps a bound peer's connection and withdraws it when that connection
  closes (QUIC keep-alive holds an idle binding open, a clean unbind flushes the
  close so withdrawal is prompt, and an ungraceful exit ages out on the idle
  timeout). This is the path that always works, the fallback a direct dial or a
  future hole punch is tried before. CLI: `constellation relay` runs the meeting
  point; `serve --relay <addr>` binds a server to it; `sync --relay <addr>`
  tunnels to a peer through it after any direct candidates fail. Tests: wire-codec
  units, plus a loopback integration test that binds, tunnels and syncs 200 KB in
  both directions, refuses a dialer with no bound peer and one of a wrong
  identity, and confirms a dropped binding is withdrawn; all run in CI because the
  relay is plain QUIC. Also verified end to end through the `horizon` binary: an
  empty replica pulled a full generation through a running relay with no direct
  address for the peer anywhere. Slim builds turn `net` off.
- Phase 5 Constellation UDP hole punching (`net` feature): a direct path between
  two peers both behind NATs, opened without relaying their traffic. The relay
  always works but carries every byte through a third host; often that is
  avoidable. A NAT that refuses unsolicited inbound packets still admits a reply
  to a mapping its own outbound packet just made, so if both peers fire toward
  each other's public address at once, each one's outbound packet opens its NAT
  and the other's, landing on that fresh mapping, gets in; the connection then
  runs directly, no relay in the path. The rendezvous brokers the coordination,
  since it already observes each peer's public address: a serving peer sends a
  PunchWait and the rendezvous holds its connection (presence as a live
  connection, like a relay binding); a dialer sends a PunchConnect; the rendezvous
  hands each the other's observed address on the same instant, so both fire
  together. One socket per peer does double duty, signalling the rendezvous and
  carrying the punch, so the mapping the rendezvous observed is the one the peer is
  punched on. The serving peer fires a throwaway probe to open its own mapping and
  accepts the dialer's real connection on the same socket, serving it with the
  unchanged accept loop; the dialer is a client-only endpoint, so the peer's probe
  finds no listener and is harmlessly dropped, and it runs the Noise handshake over
  the connection that forms. Identity stays in the Noise layer alone: the
  rendezvous brokers by the non-secret fingerprint and never holds the master, and
  the punched link runs the same NNpsk0 handshake as a direct dial, so a wrong
  identity is refused at the peer. Punching only opens against cone NATs (where the
  mapping a peer uses toward the rendezvous is the one it uses toward the peer); a
  symmetric NAT assigns a fresh mapping per destination, so the relay stays the
  fallback for those. CLI: `serve --rendezvous <addr>` now also waits to be punched
  there (alongside registering its direct address), and `sync` escalates in cost
  order, a direct dial, then a punch brokered by --rendezvous, then a --relay
  tunnel. Tests: punch wire-codec units, plus a loopback integration test (wait,
  broker, fire, then pull and push 200/150 KB over the punched link, refuse a
  dialer with no waiter and one of a wrong identity, confirm a dropped wait is
  withdrawn), all in CI because the coordination is plain QUIC. Also verified end
  to end through the `horizon` binary: an empty replica, with a direct dial forced
  to fail, pulled a full generation over a hole punch the rendezvous brokered. The
  punch only traverses a real NAT on real hosts; that is the one part loopback
  cannot prove. Slim builds turn `net` off.
- Phase 2 Cells confinement primitive (`cells` crate, Linux): bubblewrap-class,
  unprivileged process confinement, the cage that makes "no ambient authority"
  real. A Cell places a payload in fresh user, mount, pid, net, ipc, uts, and
  cgroup namespaces with an empty default world: a tmpfs root holding only the
  binds granted into it, no network (an empty net namespace), no devices, plus
  no_new_privs and a seccomp-bpf filter. It is unprivileged and no-SUID: a user
  namespace maps the caller to root inside the cell, so no real root and no
  setuid helper are needed (the bubblewrap design, chosen over Firejail). The
  channel a broker uses to reach a confined principal is fd passing: `keep_fd`
  keeps exactly the granted fds open in the payload and closes everything else,
  which is how a brokered file or socket reaches a principal that has no other
  authority, making weave's `Lease` real. The supervisor forks an init child
  that builds the namespaces, writes its own uid/gid map, and pivots into the
  tmpfs root, then forks the payload as PID 1; a two-pipe protocol turns any
  setup or exec failure into a typed error instead of a bare nonzero exit.
  Linux-gated deps (nix, libc, seccompiler) so the workspace still builds on
  darwin; seccompiler assembles the filter for the host arch, so the same source
  filters on x86-64 and aarch64. Tests prove the cage: a sealed cell sees no host
  files (only a bind lets one in), a read-only bind cannot be written, the cell
  cannot reach the network, seccomp refuses a blocked syscall, a handed-in fd
  works inside, and the exit code propagates; all pass both as root and as an
  unprivileged user (uid mapped to root inside). The suite skips gracefully where
  the kernel forbids unprivileged user namespaces (a hardened host or a
  restricted CI runner), so it stays green everywhere. Built and tested on a
  Linux container driven from the darwin host.

## Next

- Finish Phase 2 on a Linux host: the cells confinement primitive is done
  (above). Next is the broker seam, where the weave broker hands a confined
  principal a brokered fd over a Unix socket: materialize a Lease into an open
  file (rights-mapped flags) or a connected/bound socket, then pass it with
  SCM_RIGHTS to a principal that has no other authority, and confirm the use
  lands in the audit log. Then exec of real principals (a private /proc and a
  minimal /dev mounted from PID 1 inside the cell) and a `horizon cell` demo over
  the audit log. Linux-only, so build and test there, not on darwin.
- Glass: the live transparency surface over the weave audit log. It lands with
  the shell in Phase 3 (it is an L5 compositor surface); `horizon weave
  audit/grants` is the headless stand-in until then.
- Phase 3: shell + Wayland compositor (Smithay/iced). Linux-only.
- Phase 5 Constellation real-host verification: the whole networking stack that
  can be built and tested on one host is done and in CI, the QUIC + Noise
  transport, serve/sync CLI, concurrent multi-peer serving, mDNS LAN discovery,
  the rendezvous, the relay, and the UDP hole-punch coordination, several of them
  also verified end to end through the binary. What is left needs real hosts
  behind real NATs: proving a hole punch actually traverses one (the coordination
  and the simultaneous open are tested over loopback, but loopback has no NAT to
  cross), seeing which NAT types it opens against, and confirming the relay
  fallback carries the symmetric ones it cannot. Real-host and network work.
- Phase 5 Reconstitution boot/identity wiring: bind recovery shares to FIDO2
  re-enrollment and the boot-time unlock path, and a phone as a post-boot trusted
  device. Linux-only; the secret-sharing core and CLI are done and cross-platform.
