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
- Phase 2 Cells broker fd-passing seam (`cells::portal`, Linux): the channel that
  makes weave's `Lease` real. A confined principal's one ambient channel is a
  Unix socket to the broker; it sends a resource and rights, the broker checks
  the request against the capability it holds (weave `access()`), materializes
  the resulting Lease into a real fd (an open file with rights-mapped flags, or a
  connected socket for a Net grant), and passes that fd back over SCM_RIGHTS. The
  principal ends up holding a working fd it could never have opened itself: the
  cell has no path to the file and no route to the host, only what the broker
  chose to hand it, and the access lands in the audit log. `Cell::spawn` and
  `Child::wait` let the broker serve a principal over the kept socket while it
  runs. Tests prove the seam end to end: a confined principal that cannot open a
  host file by path reads it through a brokered fd, and one with an empty network
  namespace sends bytes over a brokered socket to a local listener; the file
  access shows up as a use on the grant. Green as root and as an unprivileged
  user. weave is a Linux-only dependency of cells (the seam is Linux fd passing),
  so the workspace still builds on darwin.
- horizon cell demo (`horizon cell demo`): a scripted walk, like `weave demo`,
  that makes the whole Phase 2 story visible at the command line. It grants a
  principal read on a file, spawns a Cell with no filesystem, no network, and no
  devices, handed only one socket to the broker; the confined principal fails to
  open the file by path, asks the broker, receives an fd it could not have made
  itself, reads through it, and the grant and use show up in the audit log (the
  Glass stand-in). cells is a cross-platform dependency of the horizon CLI but the
  demo is Linux-gated, so on other hosts it says confinement is unavailable rather
  than failing. Verified through the binary as both root and an unprivileged user.
- Phase 2 Cells exec of real principals (`cells`, Linux): a real program, not just
  an in-process closure, runs confined in a Cell, which closes Phase 2 userland. A
  Cell's `Payload::Exec` execs a dynamically linked host binary inside the cage,
  for which it needs a world richer than the empty tmpfs: a private /proc and a
  minimal /dev. Both are now mounted by the cell's PID 1 (child B), which is why
  the work waited for the exec path. The supervisor restructured so B builds the
  whole world (tmpfs root, binds, /dev, /proc) and pivots last, with child A
  reduced to creating the namespaces and the uid/gid map: /proc must be mounted
  from inside the new pid namespace and A is not in it (only its children are), and
  the /dev nodes are binds of the host's that only resolve before the pivot detaches
  the host, so both belong to one process, B. /proc is a fresh procfs bound to the
  cell's own pid namespace, so it shows only the cell's processes; /dev is null,
  zero, full, random, urandom, and tty bound from the host (an unprivileged user
  namespace cannot mknod its own nodes) plus the usual /dev/fd and std-stream
  symlinks. Binding the host's read-only system directories needed the bubblewrap
  read-only-remount fix: a remount in a user namespace cannot drop the flags the
  source mount already locked (nosuid, nodev, relatime), so the ro remount now
  reads them back with statvfs and re-asserts them, or it is refused with EPERM.
  `Cell::bind_host_system` bundles the standard read-only system dirs that exist
  plus /proc and /dev so an ordinary binary can find its interpreter, libraries,
  and ld.so cache. Tests prove exec end to end: a real dynamic binary (cp) runs in
  a cell, reading a read-only bind and writing a read-write bind; /proc is private
  (cp copies /proc/self/comm and it reads back "cp"); /dev works (cp copies
  /dev/null to an empty file). Green as root and as an unprivileged user.
- horizon cell run (`horizon cell run [--ro SRC[:DST]] [--rw ...] -- <cmd>`): run
  an ordinary command confined. It binds the host's read-only system, mounts a
  private /proc and /dev, leaves an empty network namespace and no host data, hands
  in any extra binds asked for, and propagates the command's exit code so the cell
  is transparent to a caller. Linux-gated like the demo; other hosts say
  confinement is unavailable. Verified end to end through the binary as both root
  and an unprivileged user: the cell root holds only the bound system dirs, /proc,
  and /dev (no /work, /root, or /home), the network namespace is empty, the
  unprivileged caller is mapped to root inside, and a nonzero exit comes back.
- Phase 3 compositor headless core (`compositor` crate, Linux): the start of the
  experience layer (L5), a real Wayland server built on Smithay that real clients
  connect to, holding the protocol and scene logic a display backend later sits
  on. It advertises the core globals every app needs, wl_compositor,
  wl_subcompositor, wl_shm, xdg_shell, wl_seat (keyboard + pointer), and wl_output
  (with xdg-output), over a Unix socket under $XDG_RUNTIME_DIR, and tracks every
  xdg toplevel in a Smithay desktop Space: new_toplevel maps a window and the
  client's initial commit is the cue to send the xdg configure, toplevel_destroyed
  (with a Space refresh as the backstop for a client that vanished) unmaps it. It
  does not paint yet, deliberately. The protocol and the scene are the part that
  can be proven without a display or a GPU, so they are built and CI-tested
  headlessly here, while the on-screen backend (a winit window nested in an
  existing session, then a real DRM/KMS backend) needs real hardware and is
  verified by eye next, the same split the Constellation used: its whole
  networking core is tested on one host and only NAT traversal waits for real
  machines. Only Smithay's wayland_frontend + desktop features are pulled, so the
  Wayland stack is pure Rust plus one system library, libxkbcommon, which the seat
  keyboard needs to compile an xkb keymap; the renderer and the display backends
  stay out. Linux-gated like cells, so the workspace still builds on darwin (where
  available() is false and there is no Compositor). Tests prove it end to end with
  a real in-process Wayland client and no display: the server advertises the core
  globals, and a client that opens a titled xdg toplevel sees it mapped into the
  scene and then dropped on destroy. Green as root and as the unprivileged dev user.
- horizon compositor run (`horizon compositor run`): start the headless compositor
  and watch it manage clients at the command line, the way `weave demo` and `cell
  demo` make their subsystems visible. It prints the WAYLAND_DISPLAY to point
  clients at (falling back to a private runtime dir when a bare shell has none),
  then logs each window as it maps and unmaps. Without a renderer it shows no
  pixels, but the scene graph is real, so connecting any Wayland client and
  watching its window appear and leave the log exercises the whole server. Linux-
  gated like the cell commands; other hosts say the compositor is unavailable.
  Verified end to end through the binary: a real client opened a titled toplevel
  and the compositor logged it mapping and then unmapping.
- Phase 3 compositor software rendering (`compositor` `render` feature, Linux):
  the step that turns client buffers into pixels, kept on the same split as the
  rest of the compositor, the part that can be proven without a display is built
  and tested headlessly. A pixman renderer (a pure software rasterizer, no GPU)
  imports each mapped surface's shm buffer (the commit handler now runs Smithay's
  `on_commit_buffer_handler` under this feature) and composites the Space into an
  offscreen Argb8888 framebuffer, which is then read back. The compositing lives
  in one generic `paint_space` so the exact same code paints the offscreen pixman
  buffer here and the on-screen GLES window the winit backend presents; only the
  render target differs. The proof is a headless test, no display and no GPU: a
  real in-process Wayland client attaches a 64x64 opaque-magenta shm buffer to a
  toplevel, the compositor imports and composites it, and the read-back pixels are
  asserted exactly, magenta where the window maps and the clear colour (opaque
  black) everywhere else. So "windows become pixels" is proven the same way the
  protocol is, automatically, in CI. The default build stays renderer-free; the
  one system library this adds is libpixman. Green as root and as the unprivileged
  dev user. `horizon compositor screenshot` (behind the CLI's `compositor-render`
  feature) makes it visible: it composites one frame of whatever clients have
  mapped and writes a PPM image, the headless way to actually see what the
  compositor draws (the software renderer needs no display, so the image opens
  anywhere). Verified through the binary: it writes a valid 1920x1080 PPM (the
  clear colour when no client has connected); the headless test above is what
  proves a connected client's window composites into those pixels exactly.
- Phase 3 compositor on-screen winit backend (`compositor` `winit` feature,
  Linux): present the composited scene in a real window nested inside an existing
  Wayland or X session, the first time Horizon windows are visible on a screen.
  It runs Smithay's winit backend with a GLES renderer; the render loop drives the
  same `paint_space` the headless test asserts on, so the compositing is already
  test-covered and only the windowing and the GL present are new (it is a viewer
  for now: it shows every client window but does not yet forward input to them).
  The Wayland, EGL, and GL it pulls are pure-Rust bindings loaded at runtime, so
  it builds with no extra system libraries and is compile-checked in CI; running
  it needs a display and a GPU, so it is verified by eye on a real Linux session,
  the one part CI cannot prove, exactly the split the Constellation uses where its
  whole networking core is tested on one host and only NAT traversal waits for
  real machines. `horizon compositor show` (behind the CLI's `compositor-winit`
  feature) runs it. Built and compile-checked from the Linux container on this
  darwin host, which has no display; the on-screen result awaits a real Linux
  session for eye-verification, and a real DRM/KMS backend for bare metal comes
  after.
- Phase 3 compositor input routing (`compositor`, Linux): forward keyboard and
  pointer input to client windows, so the on-screen viewer is usable, not just a
  picture. The seat already carried a keyboard and a pointer; now the `Compositor`
  drives them. `pointer_motion` refocuses the pointer on the surface under the
  cursor (the seat sends the client enter/leave and motion), `pointer_button`
  clicks and on a press gives the keyboard to the window under the cursor (raising
  it and marking it xdg-activated, the rest not), `pointer_axis` scrolls, and
  `keyboard_key` forwards keys to that focus. The focus policy is the usual one:
  pointer focus follows the cursor, the keyboard is click-to-focus. This routing
  is not tied to a backend: a display backend feeds it raw events (the winit
  backend now translates winit's `WinitEvent::Input`; a libinput one on bare metal
  later), so, like the compositing, it is proven headlessly. A new CI test drives
  the input methods directly against a real in-process Wayland client that maps a
  buffer and binds the seat, and asserts the client receives the right events: a
  pointer enter on its own surface, a motion, a BTN_LEFT press, and, where the
  seat has an xkb keyboard, a keyboard enter and a KEY_A press; the held-button
  pointer grab and the evdev/xkb keycode offset (Wayland codes sit 8 below xkb's)
  are handled, and the keyboard checks are skipped where the host has no xkb data.
  It also fixed a real bug the input path exposed: the commit handler never called
  `Window::on_commit`, so a window's cached bbox stayed zero and nothing was
  hit-testable; rendering never noticed (it walks the surface tree directly) but
  pointer focus did. The winit backend's input translation needs a display, so it
  is compile-checked in CI and eye-verified later, exactly like the on-screen
  present. Green as root and as the unprivileged dev user.
- Phase 3 compositor bare-metal DRM/KMS + libinput backend (`compositor` `udev`
  feature, Linux): drive a real display directly off the GPU, with no Wayland or X
  session to nest in, the path Horizon boots into on hardware. It sits on the same
  split as the rest of the compositor, so almost none of it is new logic: the
  frame is the same `space_render_elements` the headless render test asserts on,
  now extracted from `paint_space` and handed to a Smithay `DrmOutput`, and the
  input is the same seat routing the headless input test drives, now fed by
  libinput. What is new is only the plumbing a screen needs, and that is the part
  that waits for hardware: taking the GPU and the input devices through a seat
  (libseat) so it runs without real root, picking the primary GPU off udev,
  scanning the first connected connector for its preferred mode and a CRTC that
  can drive it, a GBM-backed GLES renderer through Smithay's multi-GPU manager (the
  path that wires the EGL context, dmabuf import, and scanout formats even for one
  card), and a page-flip-driven present loop (render the scene, queue the frame,
  retire it on the vblank, repeat) that drives the Wayland server between frames
  exactly as the winit loop does. libinput's relative pointer motion is accumulated
  into a cursor clamped to the output, and its evdev keycodes (which Smithay lifts
  to xkb codes, +8, the same convention winit reports) are mapped back down for the
  seat. Single GPU, single output, no hotplug; multi-GPU, connector hotplug, and
  VT-switch buffer recovery come later, but the seat routing and compositing they
  would feed are already done and tested. Unlike winit (whose Wayland/EGL/GL are
  pure-Rust runtime-loaded bindings), this links real system libraries: libdrm,
  libgbm, libinput, libseat, and libudev, now installed in CI. Running it needs a
  real GPU and a seat, so, exactly like the winit backend, it is compile-checked in
  CI (a `cargo build` plus clippy of the `udev` feature) and eye-verified on bare
  metal next. `horizon compositor drm` (behind the CLI's `compositor-udev` feature)
  runs it from a console. Built and compile-checked from the Linux container on
  this display-less darwin host.
- Phase 3 compositor DRM hardening (`compositor` `udev` feature, Linux): the
  bare-metal backend, first written single-GPU/single-output/no-hotplug, is now
  multi-GPU and hotplug-aware and recovers across a VT switch. Reactivating after a
  VT switch re-acquires DRM master and reset_state()s every device and surface
  (activate(true)), then drops the now-stale swapchains (reset_buffers) so the next
  frame reallocates and reprograms the mode; the frame in flight when the session
  paused never gets its vblank, so its pending flag is cleared and a fresh full
  frame is drawn. The one-shot single-device scan became a udev-driven model: a
  UdevBackend enumerates the GPUs at startup and watches for changes, so every GPU
  udev reports is brought up (multi-GPU), a GPU hotplugged in or out is added or
  dropped, and each device rescans its connectors on a udev change, so plugging or
  unplugging a monitor lights or drops its output. Each GPU keeps its own DRM
  output manager, its render node in the one shared multi-GPU manager, and its own
  vblank source; every connected connector takes a free CRTC at its preferred mode,
  several outputs per device are supported, and the present loop renders each
  output that is not waiting on a page flip, retiring it on its own vblank. Because
  clients here attach shm (CPU) buffers, a window composites on whichever GPU
  drives the output with no cross-GPU buffer sharing, which is what keeps multi-GPU
  simple. Still on the same split: compile-checked and clippy-clean under the udev
  feature in CI, eye-verified on hardware next. Left for later: a display-only
  secondary GPU (render on one card, scan out on another, the one cross-GPU case
  shm sidesteps) and a real multi-monitor logical layout (outputs mirror the single
  scene for now). Built and compile-checked from the Linux container on this
  display-less darwin host.
- Phase 3 Glass model layer (`glass` crate): the live transparency surface over
  the Weave audit log, the pane that makes "no ambient authority" something you can
  watch. The broker hands out two flat things, the live grant table and the
  hash-chained audit log, and neither is what a human reads; Glass folds them into
  a per-principal map of channels, one row per thing a principal can reach (a
  network host, a file, a device, a service), each carrying its status, how often
  it was used, the sub-resources actually touched, and the grant behind it, which
  is the kill switch. `build` is a pure fold over those two inputs plus a clock
  reading, so the whole model is reproducible and tested without a display: the
  grant table is authoritative for rights, status, and the use count, and the log
  supplies activity times, the touched sub-resources, denials, and the timeline. A
  channel is grant-backed (live, severed, or expired, and it carries the grant id
  to sever) or blocked (a denial with no live grant, the "something tried and was
  refused" signal). A denial that a grant covers folds into that grant's row
  (`covers` is the same predicate the broker used to decide, so the attribution
  matches the authorization that was refused), while an out-of-scope denial is its
  own blocked row, so a use after revoke shows as the severed channel with a
  blocked attempt on it but a reach for /etc/shadow shows as its own blocked line.
  Live authority is always shown; dead history (severed, expired, blocked) is
  bounded to the window, and a 7-day timeline buckets activity by day. The kill
  switch is `Glass::sever`, which revokes the grant: idempotent, logged like every
  other broker action, and it survives a reopen because the revocation is in the
  log. `report::text` renders the model as a dashboard (totals, an activity
  sparkline, then each principal and its channels), the headless stand-in for the
  drawn surface the same way `horizon weave audit` stands in for the log. Because
  weave is cross-platform, glass is too, so unlike the compositor it builds and is
  tested on darwin directly, not only in the container: 7 unit tests (empty inputs,
  a grant-plus-use becomes a live network channel, a denial with no grant is
  blocked, a use after revoke folds into the severed channel, an out-of-scope
  denial is its own row, dead history outside the window is dropped while live
  stays, timeline bucketing) and 2 end-to-end against a real broker (grant, use,
  deny, revoke, then build the model and pull the kill switch; and severing
  survives a store reopen). `horizon glass show [--days N]` renders the view and
  `horizon glass sever --grant <id>` is the kill switch; verified end to end through
  the binary on a scripted store (three principals, live network and data channels,
  a directory grant showing its touched files, an out-of-scope blocked attempt, then
  a severed channel after the kill switch). The same Model drawn as a compositor
  surface comes when there is a screen to verify it on, the same split the rest of
  Phase 3 uses.
- Phase 3 Glass raster surface (`glass` crate, cross-platform): the drawn
  transparency view, the same Model the text report shows turned into pixels, on
  the same headless split as the rest of Phase 3. `surface::layout` is a pure fold
  of the Model into a `Scene` of positioned rectangles and text runs (a status-
  colored tab and label per channel, the per-principal blocks with their touched
  sub-resources, the timeline as bars, the colored totals header, and an Aura
  intent line at the bottom as the launcher/command palette), and the scene also
  carries hit targets, so a click on the drawn surface resolves back to an action
  (severing a channel) the way the text view's grant id does. `raster::rasterize`
  turns that scene into an RGBA `Pixmap` in pure software: alpha-blended rectangles
  and the legacy 8x8 bitmap font (the one new dependency, font8x8, is pure glyph
  data) stamped at an integer scale, the minimal developer/Linux look the rest of
  the system uses. Both are pure and run on darwin, not only in the container, so
  the surface is unit-tested without a display (rect fill and clipping, the known
  lit pixels of a glyph, cell advance, alpha blend, and a live model rasterizing to
  a green pixel) and, more usefully on a display-less host, can be written to an
  image and looked at: `horizon glass render <store> [--days N] [--out f.ppm]
  [--width --height --scale]` draws the view to a PPM. The choice was native
  Smithay rasterization over an iced + wgpu client so the drawing stays on the
  headless-testable, GPU-free split (the container has no GPU); the compositor's
  only remaining job is to upload that Pixmap as a texture and put it on a screen,
  the thin plumbing that waits for hardware, exactly as winit/DRM are thin plumbing
  over the tested compositing. 12 new surface and raster unit tests (glass now 19
  unit plus 2 end-to-end). Verified end to end through the binary on a scripted
  four-principal store (live network, data, and device channels, a directory grant
  showing its touched files, an out-of-scope blocked attempt, and a severed
  channel), rendered to an image and eye-checked.
- Phase 3 compositor shell background (`compositor` `render` feature, Linux): the
  compositor can draw a full-screen image behind every client window, the seam the
  Glass home surface (the L5 desktop) hangs on. `Compositor::set_shell_background`
  takes a raw RGBA buffer (the bytes `glass::Pixmap` produces) and `paint_space`
  uploads it to a renderer texture and draws it into the cleared frame before the
  window elements, so windows composite over it. It is held as raw bytes and drawn
  with a direct `render_texture_at`, not as a cached `MemoryRenderBufferRenderElement`,
  on purpose: that element requires `R::TextureId: Send`, which the pixman texture
  is not, while a freshly imported texture drawn directly needs no such bound, so
  one path serves both the software (pixman) and GLES renderers. On the usual
  split: the headless pixman path is asserted in CI (a background with no client
  fills the frame, and clearing it returns to the clear colour), so the new code is
  proven without a display; the winit backend feeds it the same background (eye-
  verified on a screen later); painting it on the bare-metal DRM backend, whose
  present loop renders an element list rather than a frame, is the one remaining gap
  (it needs the `Send`-able multi-GPU texture path). End to end through the binary:
  `horizon compositor screenshot --background <store>` renders that store's Glass
  surface as the shell background and composites any client windows over it into a
  PPM, the headless way to see the Horizon desktop; verified by rendering a scripted
  four-principal store's Glass desktop at 1920x1080 through the compositor and eye-
  checking the image.
- Phase 3 Glass shell click-to-sever (`compositor` + `glass` + `horizon`): the drawn
  Glass desktop is now interactive, the kill switch you can click. The compositor
  reports a pointer press that lands on no client window as a shell-background click
  in output-logical pixels (`Compositor::take_shell_click`); it stays a generic
  substrate, knowing nothing of Glass or Weave, only that the shell was clicked
  there. Horizon, which already draws the Glass surface as that background, keeps the
  `Scene` it laid out and resolves the click through the already-tested
  `Scene::action_at` to an `Action::Sever(grant)`, severs it through `Glass::sever`
  (the same revoke `glass sever` does), then re-summarizes the broker, relays the
  surface out, and hands the new pixels back so the desktop redraws with that channel
  now severed. Layering holds: the click primitive is pure input (not render-gated),
  the Glass mapping lives in the binary where both crates meet, and the on-screen
  winit loop carries it through a closure (`Compositor::show` now takes an
  on-shell-click handler returning the refreshed background). On the usual split, the
  compositor primitive is proven headlessly (a press on empty space reports its
  coordinates and clears when taken, a press over a client window does not, the
  window wins) and the whole resolve-and-sever chain is proven headlessly against a
  real broker in glass (lay the model out, click the `sever` button's rect, it
  resolves to that grant, sever it, and the rebuilt model shows the channel severed);
  the winit wiring is compile-checked under the feature and eye-verified on a screen
  later, the same bar as the rest of the backend. `horizon compositor show
  --background <store>` draws the clickable Glass desktop. The coordinates line up
  because the shell renders at output scale 1, so a logical click indexes the
  surface's own pixels directly.
- Phase 3 Glass desktop on the DRM backend (`compositor` `udev` feature + `horizon`):
  the bare-metal path now draws the Glass shell background behind client windows and
  routes a `sever` click through the broker, the same clickable desktop the winit
  backend shows, now straight off the GPU. The winit/pixman `paint_space` draws the
  background by uploading it and calling `render_texture_at` directly, but the DRM
  present loop hands `DrmOutput::render_frame` a homogeneous element list, so the
  background has to be a `RenderElement`. It becomes a `MemoryRenderBufferRenderElement`
  (the CPU-bytes-to-scanout path), unified with the window surfaces under one
  `render_elements!` enum (`ShellElement`, Surface or Background) and appended last so
  it sits behind the windows (render_frame draws front to back). That element needs
  `R::TextureId: Send`, which the multi-GPU renderer's `MultiTexture` is but the pixman
  texture is not, which is exactly why this path is DRM-only and the pixman one draws
  directly. The upload is cached: a `MemoryRenderBuffer` is rebuilt only when the
  compositor's background generation changes (`set_shell_background` bumps it), so an
  idle desktop is not re-uploaded each frame, which would pin the GPU at full redraw
  and defeat the backend's damage-based present skip; the buffer re-uploads only its
  damaged regions and caches the texture per GPU context, so one shared buffer serves
  every output and GPU. The sever click is wired exactly as winit: `run_drm` now takes
  the same `on_shell_click` closure, the loop offers each press that hit no client
  window to it and sets any returned redraw as the new background. The enum is built in
  a small submodule because `render_elements!` expands to a bare `Result` that would
  otherwise bind to the crate's `Result` alias. `horizon compositor drm --background
  <store> [--days N]` draws the clickable desktop on bare metal, the interactive
  `Shell` now shared by `show` and `drm`. Same split as the rest of the DRM backend:
  compile-checked and clippy-clean under `udev` in CI, eye-verified on hardware next,
  while the pieces it composes are already headless-tested (the click primitive in the
  compositor, the resolve-and-sever chain in glass, the background compositing on the
  pixman path). The shell renders at the compositor's logical output size and is drawn
  at the output origin, so on a larger monitor it sits top-left, the same single-scene
  limitation the rest of the DRM backend has. Built and compile-checked from the Linux
  container on this display-less darwin host.
- Phase 3 Glass shell live refresh (`weave` + `compositor` + `horizon`): the drawn Glass
  desktop now reflects changes made to the store from OUTSIDE the shell, not only an
  in-shell sever click. The honest problem was that the shell holds one in-memory broker
  opened once, so it never saw appends another process (a `horizon weave grant`, a cell
  reaching a resource, an external `glass sever`) made to the same audit log. The core is
  `Broker::reload`: it re-reads the one audit ref and, only if the head changed since the
  broker last looked, re-replays the chain to rebuild the live grant table, returning
  whether anything changed. It is cheap on an idle store (a single small ref read, no
  chain walk, no grant touched) because every Lifestream read already goes to disk, so a
  long-lived broker folds in out-of-band writes just by re-reading; the replay shares one
  fold with `open`, so a reloaded grant carries no session secret exactly as a reopened
  one does. The compositor offers the shell owner a periodic `Tick` alongside the existing
  background `Click`, unified into one `ShellEvent` closure both `show` and `run_drm` take
  (one closure, not two, because the owner holds the shell behind a single mutable borrow);
  each loop iteration offers a tick and uploads any returned redraw. The horizon `Shell`
  owns the cadence: `refresh` rate-limits to a 500ms poll, calls `Broker::reload`, and
  relayouts and redraws only when it reports a change, so an idle desktop re-uploads
  nothing and a live one keeps its clickable scene in sync with the store. On the usual
  split, the testable core is proven headlessly on darwin and Linux: a weave test that
  `reload` picks up a second broker's grant and revoke and is idempotent, and a glass test
  that the Model is stale until the broker reloads and then reflects an external grant
  (open a store, append externally, re-summarize, assert the model changed); the winit/drm
  tick wiring is compile-checked and clippy-clean under the features and eye-verified on a
  screen later, the same bar as the rest of the backend. `horizon compositor show
  --background` and `drm --background` now say the desktop refreshes live. Built and
  compile-checked from the Linux container on this display-less darwin host.
- Phase 3 Aura command palette (`glass` + `compositor` + `horizon`): the Glass intent
  line at the bottom of the desktop is now a real launcher and command palette, the way
  you act on the desktop with no client window in front. Three layers, each on the usual
  headless split. (1) `glass::aura` parses a typed line into a `Command` (launch an app,
  sever channels by name, filter the view, help) and resolves that command against the
  live Model into a `PaletteAction` plus a view filter and a one-line hint, both pure; a
  `Palette` holds the editable input buffer and the text cursor (insert, backspace,
  delete, cursor moves, UTF-8 safe), also pure. (2) `surface::layout` now takes the
  palette: it draws a two-row band (the prompt, the typed line, and a caret at the
  cursor, then a feedback row showing the resolved hint) and narrows the principal list
  to the palette's filter, so typing previews what a command will hit; the sever-button
  hit targets still resolve clicks as before. (3) the compositor routes keystrokes to
  the shell when no client holds keyboard focus (the desktop itself is focused, which a
  background click already selects by clearing client focus): `keyboard_key` translates
  the xkb keysym to a `ShellKey` (a character or a named editing key) and records it
  instead of forwarding, `take_shell_keys` drains them, and a new `ShellEvent::Key` arm
  carries each to the owner through the same one closure `show` and `run_drm` already
  take for clicks and ticks. The horizon `Shell` ties it together: it caches the Model so
  a typed line resolves without a store read per keystroke, edits the palette on each key
  and re-previews, and on Enter runs the command, launching a Wayland client (a plain
  spawn connected to this compositor's WAYLAND_DISPLAY, with Cell confinement the next
  step since the cells exec path is ready) or severing every matching live channel
  through `Glass::sever`, then redraws; launched apps are reaped on the poll tick. The
  testable core is proven headlessly: glass unit tests for parse, resolve, and the
  palette buffer (including multibyte edits), surface tests that the typed line, the
  hint, and the filtered list render, a glass end-to-end test that a typed `sever <name>`
  resolves against a real broker to the right grants and severs them (the sibling of the
  click-to-sever test), and a compositor headless test that with no client focused the
  keystrokes are reported to the shell, translated, while a focused client still gets its
  keys (gated on the seat having xkb data, like the existing keyboard test). The key
  routing and the actual app spawn are the only parts that need a screen, eye-verified
  next, exactly as the rest of the backend is. Built and tested on darwin and in the
  Linux container.
- Phase 3 Aura palette client confinement (`cells` + `horizon`): a client launched from
  the palette now runs confined in a Cell, not a plain spawn, so it starts with no ambient
  authority, no host files, no network, no devices. Its one channel is the Wayland
  connection to this compositor, which is the display capability you grant by launching it
  (the compositor mediates everything over that socket); any further authority is a Weave
  grant brokered later, not something the app holds by virtue of running as you. Reaching
  the display from the empty world takes two things, both already built: `bind_host_system`
  for the interpreter and libraries, and the compositor's Wayland socket bound in writable
  at the one path the client's env points at (`XDG_RUNTIME_DIR=/run/horizon` +
  `WAYLAND_DISPLAY=wayland-0` resolve to exactly the bind target, the invariant a confined
  client relies on). The net namespace stays empty: a Wayland socket is a pathname Unix
  socket, a filesystem rendezvous rather than a network one, so connecting to it crosses an
  empty network namespace (an abstract socket or real networking would not); no host data
  is bound (no home, no other runtime-dir contents). A GPU client would also need a render
  node (`/dev/dri`), deliberately withheld, so it cannot reach the GPU; an shm client, what
  the compositor imports, composites fine. `cells` gained `Child::try_wait` (a non-blocking
  reap) so the long-lived shell collects exited confined clients on its poll tick (the
  cell's init child is a direct child and must be collected), plus a `Cell::binds()` read
  accessor so a construction is assertable without spawning. On the usual headless split the
  cell construction (binds + env) is pure and asserted with no screen, and a headless test
  proves the harder claim, that the empty net namespace still reaches the display, by
  connecting through the bound socket from inside a real cell; only the client actually
  mapping a window needs a screen, eye-verified next. This also closes a CI gap: the horizon
  Glass shell is feature-gated, so the default build never compiled it and only local gates
  did; a new CI step lints and runs it under the winit feature. Tests: a `cells` unit that
  `try_wait` reports running while the payload blocks then returns the exit code with no
  blocking wait, and horizon units for the host socket path, the env-points-at-the-bound-
  socket invariant, and that the cell binds the socket plus the read-only host system and no
  home, then the connect-through-the-bind end-to-end. Built and tested on darwin and in the
  Linux container.
- Phase 3 compositor multi-monitor logical layout (`compositor`, Linux): real
  multi-monitor support, the second of the two DRM gaps (the first, a display-only
  secondary GPU, remains). Outputs no longer mirror the one scene from the origin;
  each is placed in one shared logical coordinate space and scans out only its own
  region, so a window lives at a single position across the whole desktop and the
  screens span it instead of all showing the same pixels. The testable core is two
  pure pieces. (1) `compositor::layout` is the arrangement policy: `arrange` lays
  outputs left to right, top-aligned, returning each one's logical position, and
  `span` gives the cursor's bounding box; plain integers, no Wayland types, so it
  builds and unit-tests on darwin too, not only in the container. (2)
  `render::output_render_elements` crops and offsets the shared `Space` to one
  output's geometry through Smithay's `render_elements_for_region`, the same
  elements the DRM backend scans out, so the paint path now has a single-output
  collector (the whole space from the origin, for winit and the headless
  `render_space`) and a per-output one (one output's region), both feeding one
  `composite` core. On the usual headless split the whole thing is proven without a
  display: a new id-based output API (`Compositor::add_output` / `move_output` /
  `render_output`, render-gated) places several outputs in the shared space and
  reads each back through the software renderer, and two tests assert a window shows
  only on the output whose region covers it (not mirrored onto the others) and that
  moving an output shifts the region it renders, alongside 5 layout units. The DRM
  backend now maps each lit connector into the shared space at its layout position
  (`relayout`, recomputed on monitor or GPU hotplug, the primary GPU's outputs
  sorted first so the primary monitor sits at the origin where new windows open),
  renders each output's own region instead of the whole scene mirrored, and clamps
  the cursor to the full span so the pointer crosses between screens; like the rest
  of the backend it is compile-checked and clippy-clean under `udev` and
  eye-verified on hardware next. The window scene is shared; the shell background is
  still drawn per output at its own origin (each monitor shows the Glass desktop).
  Advertising each output to clients as its own `wl_output` global, and per-output
  scale, are the remaining multi-monitor gaps. Built and tested on darwin (layout)
  and in the Linux container (render + udev).
- Phase 3 compositor per-monitor wl_output globals (`compositor`, Linux): each
  output placed in the shared logical space is now advertised to clients as its own
  `wl_output` global, so a Wayland client enumerates one output per physical monitor
  and learns each one's logical position, mode, and scale, instead of seeing a
  single phantom output stretched across the whole desktop. This is the next of the
  two remaining multi-monitor gaps after the logical layout (per-output scale is the
  last). The default placeholder output (the single virtual screen the headless core
  and the winit nested window present) keeps its global only while no explicit
  output exists: the first placed output, a headless `add_output` monitor or a real
  DRM connector, retires it so clients see the real monitors and not the phantom, and
  it is restored when the last one goes away so a client still sees one screen.
  `move_output` and the DRM `map_output` keep each output's advertised location in
  step with its Space mapping (so a client sees a monitor where the layout placed
  it), and removing an output withdraws its global. On the usual headless split the
  whole client-visible behavior is proven without a display: a new test places two
  outputs through the id-based API and a real in-process Wayland client binds every
  `wl_output`, reads each one's geometry and mode (asserting one global per monitor
  at the right position and size, with the placeholder gone), and is told its window
  entered only the output whose region covers it, so the globals are real and wired
  to the shared layout, not just minted. The bare-metal DRM backend advertises each
  lit connector the same way: a global created when the connector is lit, withdrawn
  when it is unplugged or its GPU is removed, the placeholder retired while any real
  monitor exists. Because creating a global names the private server `State` the
  display handle is typed against (which the DRM module cannot reach), the create and
  withdraw are free functions in the server module that the backend calls with a
  display handle it now holds, since the connector scan has no compositor in hand.
  Like the rest of the DRM backend it is compile-checked and clippy-clean under
  `udev` and eye-verified on hardware next. Per-output scale, and a display-only
  secondary GPU, are the remaining multi-monitor and DRM gaps. The headless client
  test runs in the Linux container under `render`; the DRM half is compile-checked
  under `udev`.
- Phase 3 compositor per-output scale (`compositor`, Linux): each output carries
  its own integer scale, the last multi-monitor gap after the logical layout and
  the per-monitor `wl_output` globals. A HiDPI monitor is advertised to clients at
  scale 2 on its `wl_output`, renders its region at 2x, and occupies half its pixel
  size in the shared logical space, instead of every output being pinned to scale
  1. The DRM backend derives a scale per connector from the panel's pixel density
  (`layout::scale_for`, a pure DPI heuristic: 2x at or above ~192 DPI, double the
  classic 96 DPI baseline, and 1x for an unknown EDID size or the 150-190 DPI middle
  ground a 27-inch 4K sits in, which wants the fractional-scale protocol still to
  come), advertises it on that connector's `wl_output`, and lays outputs out by
  their logical size (mode / scale) so a 4K-at-2x monitor takes 1920 not 3840 of
  layout width and the next monitor abuts it with no gap; the cursor span is logical
  too. Rendering already read `output.current_scale()` to crop each output's region;
  the missing half was the draw scale: a surface element is sized by the scale it is
  drawn with, so the offscreen `composite` had to draw at the output scale, not a
  hardcoded 1, or a HiDPI window composited at 1x into a 2x framebuffer. The frame's
  size, scale, transform, and clear are now one `FrameTarget`, the per-output
  readback passing the output scale and the single-output winit/`render_space` paths
  passing 1 (the default output is always scale 1). On the usual headless split the
  whole client-visible behavior is proven without a display: a new test places an
  ordinary and a HiDPI output and a client reads scale 1 off the first and 2 off the
  second (each still advertising its full pixel mode, the client deriving the
  logical size mode/scale), and a second test renders a scale-2 output's region and
  asserts the 64-logical window composited to 128 physical pixels (magenta at
  100,100, which would be the clear colour at 1x), so the scale flows all the way to
  the pixels, not just the advertisement. The `scale_for` heuristic is pure
  integer-and-float math, unit-tested on darwin (ordinary desktop monitors stay 1,
  high-density panels get 2, a 27-inch 4K stays 1 until fractional scaling, an
  unknown physical size stays 1). The DRM half (deriving the scale, advertising it,
  the logical layout) is compile-checked and clippy-clean under `udev` and
  eye-verified on hardware next. This closes the multi-monitor work; the one
  remaining DRM gap is a display-only secondary GPU (cross-GPU scanout). The
  headless client and render tests run in the Linux container under `render`.
- Phase 3 compositor cross-GPU scanout (`compositor` `udev` feature, Linux): a
  display-only secondary GPU, render on one card and scan out on another, the last
  remaining DRM gap after the multi-monitor work. Until now each output composited
  on whichever GPU drove it, which works only while that GPU can render; a card
  wired to a monitor but not rendered on (a hybrid laptop's iGPU, a second GPU, a
  USB display) had no path to the screen. Now every output is composited on the
  primary GPU: one whose own GPU is the primary scans out straight from it
  (`GpuManager::single_renderer`, no copy, so the single-GPU and primary-monitor
  case is unchanged), while one driven by any other GPU is rendered on the primary
  and its finished frame copied across to that GPU for scanout
  (`GpuManager::renderer(primary, target, copy_format)`, the `MultiRenderer` doing
  the dma-or-CPU copy) in the surface's own scanout format (`DrmOutput::format`). The
  renderer is chosen per surface because the copy target and the format are per
  output. Because client buffers are shm (CPU), only the one composited frame ever
  crosses the GPU boundary, never per-window buffers, so the cross-GPU path stays a
  single copy and needs no per-surface early-import. The frame is the same
  `output_render_elements` (one output's region of the shared logical space) the
  headless render test asserts on, so only the renderer selection is new logic. A
  card that exposes a usable render node (the hybrid-graphics and second-GPU cases)
  is covered; one with no GL/EGL at all cannot be a copy target and is the remaining
  edge, rare in practice. Same split as the rest of the DRM backend: compile-checked
  and clippy-clean under `udev` in CI, eye-verified on real two-GPU hardware next (a
  single host with two GPUs is the one thing CI and the container lack, the part
  headless cannot prove), while the compositing it reuses is already headless-tested.
  This closes the multi-monitor and DRM-backend gaps; the Phase 3 compositor backend
  is now feature-complete on the headless-buildable split, with only the on-hardware
  eye-verify left. Built and compile-checked from the Linux container on this
  display-less darwin host.
- Phase 5 identity FIDO2 keyslots (`identity` crate + `horizon`): unlock a store's
  master key with a FIDO2 security key, not only the passphrase, and make recovery
  shares the way to enroll a fresh key when one is lost. Everything in Horizon turns
  on one 32-byte master (the Lifestream derives its keys from it, the Constellation
  binds Noise to it, Reconstitution splits it into k-of-n shares); the tools derive
  it from a passphrase via Argon2id. This adds a second way to recover the same
  master, so it is purely additive: no existing store, Lifestream, or Constellation
  state changes, and it is reversible. The core is a keyslot. A FIDO2 authenticator's
  CTAP2 hmac-secret extension returns a deterministic 32-byte secret for a credential
  it holds and a salt, gated by a touch and never leaving the device; a `Keyslot`
  seals the master under a wrap key derived from that secret (XChaCha20-Poly1305,
  blake3-derived wrap key, the credential id as AAD) and stores only the credential
  id and salt, so the sealed master plus the keyslot reveal nothing without the
  device. A store holds a `keyslots` file of independent slots (`Keyslots`), one per
  enrolled device; `unlock_any` returns the first master a slot yields. On the usual
  headless split the security-critical part is a pure core tested with no hardware:
  the sealing, the file format, and slot selection sit behind an `Authenticator`
  trait, exercised against a `SoftwareAuthenticator` (a deterministic token a holder
  keeps in a file, the test and dev seam, not hardware-backed). The real USB-HID
  authenticator (`HardwareKey`, behind the `fido2` feature, Linux) is a thin
  implementation of the same trait over `ctap-hid-fido2`: a non-resident credential
  with hmac-secret at enroll, the per-credential secret read back for a salt at
  unlock; it statically builds hidapi's hidraw backend (links libudev, already
  present for the compositor's udev feature, so no new system package) and is
  compile-checked in CI and verified on a real key, exactly as the compositor's
  display backends sit behind its tested compositing core. The CLI ties it together:
  `horizon identity enroll` (master from the passphrase, sealed into a keyslot),
  `unlock` (the boot path: try the enrolled keyslots, fall back to the passphrase,
  proven by decrypting HEAD), `reenroll --share` (rebuild the master from recovery
  shares and seal it for a fresh device, the way back in for a lost key), and `list`;
  `--token <file>` uses a software token, `--fido2` a real key in a build with that
  feature. Recovery interoperates for free because shares and keyslots both yield the
  same master. Tests: 7 identity unit tests (enroll/unlock roundtrip, a wrong token
  refused, `unlock_any` over several slots, AEAD tamper rejection, encode/decode,
  version and truncation checks) and a horizon end-to-end integration test (init a
  store, enroll a token, persist and reload the keyslots, unlock, then recover the
  master from 2-of-3 shares and enroll a new token, asserting the recovered key is
  the original and opens the store), all on darwin and in the container. Also verified
  end to end through the binary: init and snapshot a store, enroll a software token,
  unlock with it with no passphrase (HEAD decrypts), split 2-of-3 recovery shares,
  reenroll a new token from two of them, unlock with the new token, and confirm an
  unenrolled token is refused and falls back to the passphrase. Left for the boot/
  identity wiring: hooking `identity unlock` into the real boot/init sequence, and a
  phone as a post-boot trusted device. Built and tested on darwin and in the Linux
  container.
- Phase 0/5 boot integration (`boot` crate + `horizon`): the seam that joins identity
  to the experience layer, so a device unlocks its master once and lands in its
  desktop on that same master, instead of unlocking and then being asked for the
  passphrase again. The honest gap it closes: `identity unlock` recovered the master
  with a touch but only printed status, while every session path (`compositor
  show/drm --background`) re-derived the master from the passphrase through
  `open_broker` -> `open` -> `master_key`, so the unlock and the session never met. A
  new cross-platform `boot` crate models the boot unlock as three pure steps over a
  store on disk: `discover` finds the one store to boot (the store itself, or the
  single store under a mount, by the `keysalt` marker every tool checks; zero or many
  is an error, never a guess at which identity to open), `unlock` recovers the master
  trying an enrolled keyslot through a present authenticator first (a FIDO2 touch or a
  software token, reusing `identity`) and falling back to the passphrase, and `prove`
  opens the Lifestream and decrypts HEAD, the same proof `identity unlock` and
  `reconstitute open` use, so a wrong key fails before any session starts; `boot` runs
  all three and returns a `Booted` (the store, the proven master, how it was
  unlocked). The passphrase KDF is lifted into `boot::derive` as the single canonical
  Argon2id derivation every tool now shares (`horizon`'s `derive` delegates to it, and
  its `argon2` dep is dropped), so a store made by `lifestream init` opens the way
  `boot` opens it with no second definition to drift. `horizon boot [--store <s> |
  --root <mount>] [--token <f> | --fido2] [--nested] [--no-session]` ties it together:
  it resolves the store, builds the authenticator if asked, runs `boot::boot`, prints
  the boot log, and launches the desktop in-process on the unlocked master, threaded
  through a new `open_broker_with(store, Some(master))` so the session opens the store
  with no second prompt (the standalone `compositor show/drm` pass None and derive
  from the passphrase as before). The desktop is the bare-metal DRM backend for a real
  boot, the nested winit backend under `--nested` for development; each exists only in
  a build with its compositor feature, and a build without it says how to get it
  rather than failing silently. On the usual headless split the whole unlock-and-prove
  core is pure logic over a store on disk, tested with no hardware: 9 `boot` unit tests
  (store detection, discovery including refuse-to-guess and the ambiguous case, the
  KDF, the keyslot-then-passphrase policy against a `SoftwareAuthenticator`, the HEAD
  proof, a wrong master rejected) and 4 `horizon` integration tests (a token unlocks
  the master and the session opens on it with no passphrase, the whole path runs
  through `boot_cmd --no-session`, the passphrase is the fallback when no token
  matches, and main's KDF agrees with `boot::derive`), all cross-platform so they run
  on darwin and in the container. The one part that needs hardware is launching the
  actual desktop on a screen, eye-verified next exactly as the compositor backends
  are; `--no-session` is the boot check that runs anywhere. Also verified end to end
  through the binary: init and snapshot a store, enroll a software token, then `horizon
  boot` unlocks it with the token and no passphrase (HEAD decrypts), discovers the same
  store under a mount, falls back to the passphrase with no token, and a wrong token
  falls back and is refused by the HEAD proof. Left for the boot wiring: a phone as a
  post-boot trusted device (a Constellation enrollment after boot), and the real
  initramfs/UEFI image Phase 0 proper builds this orchestration into. Built and tested
  on darwin and in the Linux container.
- Phase 0 init (`init` crate + `horizon-init`): the first userspace process in
  Horizon's initramfs, the step before the `boot` crate. The kernel execs one program
  as PID 1; this is that program, and its job is to turn "a kernel with a Key plugged
  in" into "the real root, mounted, with `horizon boot` running on it", i.e. it gets
  the machine to where `boot` can unlock the identity. The on-disk model is the one in
  `docs/03-PORTABILITY-AND-BOOT.md`: an immutable base image, mounted read-only, with a
  writable layer stacked over it by OverlayFS, so the base resets clean and cannot be
  corrupted by a runaway process while this machine's state goes in the writable layer.
  What that layer is made of is the whole Home-vs-Ghost decision: `Mode::Home` (a Known
  Surface) backs it with a persistent device so OS state survives a power-off;
  `Mode::Ghost` (a Foreign Surface) backs it with tmpfs in RAM so the machine writes
  nothing outside memory and the session is gone on power-off. The base is read-only in
  both modes; only the writable layer differs. On the same headless split the rest of
  Horizon uses: the policy of a boot, what to mount, in what order, where, the mode
  decision, the final pivot and exec, is pure logic (a `Recipe` is folded into a `Plan`
  of ordered `Step`s by `plan()`, and the kernel command line is parsed into `Params`,
  the `LABEL=`/`UUID=` device specs, the mode, the init, by `parse_cmdline()`, with
  `choose_mode()` degrading Home to Ghost when no persistent device is present so a
  "boots anywhere" device still comes up), so it builds and is tested on every host;
  the execution of the plan (mount, overlayfs, bind, move, switch_root, all behind
  nix) is Linux-only, so the workspace still builds on darwin. The handoff is a
  faithful initramfs switch_root: mount devtmpfs/proc/sysfs, mount the immutable base
  read-only as the overlay lower, mount the writable backing (device or tmpfs) and
  assemble the overlay root, bind the Key's identity store into the new root so
  `horizon boot` finds it, move the kernel filesystems across, then move the new root
  over `/` and exec the init. Tests on the usual split: 11 pure plan/cmdline/mode tests
  run on darwin and in the container (the base is always read-only, Ghost never touches
  the data device, the overlay stacks the writable upper on the immutable lower, the
  carry lands inside the new root, the pivot is last and execs the init); the executor
  is proven for real where there is a kernel to run it, a privileged-container test
  assembles the overlay root and carries a stand-in store, asserting the immutable
  lower is visible through the root, a write lands in the writable upper and never in
  the lower (the base resets clean), and the store is reachable in the new root. The
  final switch_root cannot run in a test (it would replace the test process's own
  root), so it is proven by booting, exactly as the compositor's display backends are.
  Left for the rest of Phase 0: dm-verity over the base (tamper-evident immutable),
  LUKS2 for the Home writable layer (encrypted persistence) and the Foreign-Surface
  store handoff (reading the identity read-only from the Key in Ghost mode), the image
  build that assembles the base + initramfs + kernel + bootloader into a bootable Key,
  and booting the whole chain in QEMU (UEFI -> bootloader -> kernel -> horizon-init ->
  horizon boot -> the DRM desktop), the real "boots anywhere and remembers" demo short
  of real metal. Built and tested on darwin and in the Linux container.
- Phase 0 base image (`keybuild` crate + `horizon-keybuild`): the host-side tool that
  assembles the filesystems of a Horizon Key, the producer side of the contract the
  `init` crate consumes. A Key carries two filesystems: an immutable base image,
  mounted read-only, holding the OS, and a persistent data partition holding the
  writable overlay layer and the identity store. keybuild writes the partition labels
  and emits the kernel command line; init finds the partitions by those labels and
  parses that command line; the two agree by sharing init's types rather than by
  convention, so to make that one definition the `HORIZON-BASE`/`HORIZON-DATA` labels
  and the test skip-predicate moved into init (`init::BASE_LABEL`, `init::DATA_LABEL`,
  `init::is_unprivileged_error`) and keybuild reuses them. This piece builds the
  immutable base: `build_base` materializes a minimal base skeleton (the standard mount
  directories and an os-release) and packs it into a squashfs built root-owned, without
  xattrs, and with every timestamp pinned, so the same skeleton yields byte-identical
  bytes and the base can be verified by hash; `boot_cmdline` emits the `horizon.*`
  tokens that `init::parse_cmdline` reads back. The build shells out to `mksquashfs` and
  does no kernel work itself, so the crate builds and the pure parts test on every host;
  only the test that mounts the result needs a Linux kernel and is gated. Tests on the
  usual split: 3 pure tests on darwin and in the container (the emitted command line
  round-trips through init's parser for every mode, the default labels are the ones init
  looks for so a Key boots with no explicit command line, the skeleton has the mount
  directories and names the system); 2 gated container tests prove the build for real,
  that `build_base` is byte-for-byte reproducible across two builds, and that the
  produced squashfs loop-mounts read-only as the init's overlay lower with a tmpfs upper
  (os-release visible through the root, a write landing in the upper, the squashfs lower
  refusing writes), the immutable-base + writable-overlay model now on the real image
  format the Key uses. Verified end to end through the binary in the container:
  `horizon-keybuild --out` writes a valid squashfs (its superblock timestamp zeroed) and
  prints the boot command line. Left next: populating the base with the real userland
  (binaries, libraries, kernel modules, firmware), the persistent data partition with an
  initialized store, dm-verity over the base, LUKS2 for the writable layer, the
  bootloader, and a QEMU boot of the whole chain. Built and tested on darwin and in the
  Linux container.

## Next

- Phase 3: the experience layer. The compositor's headless core (a real Wayland
  server: the core globals, the xdg-shell toplevel lifecycle, the scene graph),
  its software renderer (importing client shm buffers and compositing the Space
  into an offscreen framebuffer, asserted on pixel by pixel), and its input
  routing (pointer focus follows the cursor, click to focus, keys to the focused
  client) are done and CI-tested. Both display backends are now written and
  compile-checked: the on-screen winit backend (presents the scene and translates
  the window's input, nested in an existing session) and the bare-metal DRM/KMS +
  libinput backend (drives a real display straight off the GPU, the path Horizon
  boots into). Both reuse the same tested compositing and seat routing, so only
  their device plumbing is new, and that is the piece that genuinely waits for
  hardware (this host is a display-less darwin Mac driving a headless Linux
  container). The next step is the eye part: run `horizon compositor show` on a
  real Linux session to watch a client's window appear in the nested window and
  click and type into it, and run `horizon compositor drm` from a console on bare
  metal to do the same straight on the GPU. The DRM path has since been hardened
  (multi-GPU, connector and GPU hotplug, VT-switch buffer recovery), all written
  and compile-checked on the same split, so it too is waiting on that eye part. A
  real multi-monitor logical layout is now done: each output is placed in one shared
  coordinate space (a left-to-right `compositor::layout`) and scans out only its own
  region instead of mirroring the whole scene, hotplug-aware, with the cursor
  spanning all screens, proven headlessly (a pure layout plus per-output region
  rendering, read back through the software renderer with an id-based output API) and
  eye-verified on hardware next. Advertising each output to clients as its own `wl_output` global is now
  done: every output placed in the shared space (a headless `add_output` monitor or a
  real DRM connector) carries its own global at its logical position, mode, and scale,
  the phantom placeholder retired while any real monitor exists, proven headlessly by
  a client that enumerates one `wl_output` per monitor and a window that enters only
  the output it covers. Per-output scale, the last multi-monitor gap, is now done too:
  each output carries its own integer scale (the DRM backend derives it per connector
  from the panel's pixel density via `layout::scale_for`), advertised on its
  `wl_output`, applied in rendering (a HiDPI output renders its region at 2x), and
  used to lay outputs out by their logical size mode/scale so the screens abut with no
  gap; proven headlessly by a client reading scale 1 and 2 off two monitors and a
  scale-2 output compositing a window at 2x. Cross-GPU scanout, the last DRM-backend
  gap, is now done too: every output is composited on the primary GPU and one driven
  by any other GPU has its finished frame copied across to that GPU for scanout
  (`single_renderer` for the primary's own outputs, `GpuManager::renderer(primary,
  target, format)` for the rest), so a display-only secondary GPU (a hybrid laptop's
  iGPU, a second card) now lights its monitor; shm client buffers mean only the one
  composited frame crosses the GPU boundary. This makes the Phase 3 compositor backend
  feature-complete on the headless-buildable split, leaving only the on-hardware
  eye-verify. The shell proper has started: the
  compositor now draws a full-screen background (the Glass L5 desktop, a pure Model
  -> Scene -> Pixmap renderer in the `glass` crate) behind client windows, proven on
  the headless pixman path and wired into the winit backend, with `horizon compositor
  screenshot --background <store>` showing the composited desktop, and a click on a
  Glass `sever` button is now routed back through `Glass::sever`: the compositor
  reports a press that hit no client window, Horizon resolves it through the scene
  and severs, then redraws the surface, wired into `horizon compositor show
  --background`, and now on the bare-metal DRM backend too: the background is painted
  as a `MemoryRenderBufferRenderElement` behind the windows (the Send-able multi-GPU
  texture path the element-list present loop needs) and the sever click runs through
  the same shell closure, behind `horizon compositor drm --background`. The desktop now
  also refreshes live as the audit log changes from outside (the compositor offers a
  periodic `Tick` through the same `ShellEvent` closure as the click, and the shell polls
  `Broker::reload` and redraws only on a change), proven headlessly. The Aura intent line
  is now a real launcher and command palette: `glass::aura` parses and resolves a typed
  line (launch an app, sever channels by name, filter the view), `surface::layout` draws
  the input, caret, and feedback and filters the list, the compositor routes keystrokes to
  the shell when no client is focused (the new `ShellEvent::Key`), and the horizon `Shell`
  runs a command on Enter, all headless-tested. A launched client now runs confined in a
  Cell, not a plain spawn: `bind_host_system` for libraries, the compositor's Wayland socket
  bound in at the one path the client's env points at, an empty network namespace (a Wayland
  pathname socket crosses it), and no host data, so an app starts with no ambient authority
  beyond the display connection. `cells` gained a non-blocking `Child::try_wait` so the shell
  reaps exited confined clients on its tick, and the cell construction is asserted headlessly
  (including a real connect through the bound socket from inside the empty-net cell). What is
  left on the shell is only the eye-verify of the key routing and a confined client mapping a
  window on a real screen. Confined cells can already host compositor surfaces. Linux-only.
- Glass: the live transparency surface over the weave audit log. The model layer
  and the drawn surface are both done (the `glass` crate: a pure fold of the
  broker's grant table and audit log into a per-principal map of
  live/severed/blocked channels, a 7-day timeline, and the sever kill switch, then
  `surface::layout` + `raster::rasterize` turning that Model into an RGBA Pixmap
  with hit targets, all headless-testable and CI-green on darwin), with a text
  report (`horizon glass show`) and an image render (`horizon glass render`) as the
  headless stand-ins and `horizon glass sever` as the kill switch. The compositor
  blit has landed too: `Compositor::set_shell_background` uploads the Pixmap as a
  texture and `paint_space` draws it behind client windows, proven on the headless
  pixman path and wired into the winit backend (`horizon compositor screenshot
  --background <store>` shows it), and a click on a `sever` hit target is now routed
  back through `Glass::sever` (the compositor reports the press, Horizon resolves it
  through `Scene::action_at` and severs, then redraws), behind `horizon compositor
  show --background`, and on the bare-metal DRM backend behind `horizon compositor
  drm --background` (the background drawn as a `MemoryRenderBufferRenderElement`, the
  click routed the same way). It also refreshes live now as the log changes from
  outside the shell: `Broker::reload` re-reads the audit log only when its head moved,
  and the compositor offers the shell a periodic `Tick` (the same `ShellEvent` closure
  as the click) so the desktop redraws when another process grants, uses, or revokes.
  The intent line at the bottom is now the Aura command palette (`glass::aura`): a typed
  line parses and resolves to launch an app, sever channels by name, or filter the view,
  drawn with a live caret and the resolved hint, fed by the compositor's `ShellEvent::Key`
  when no client is focused; parser, resolver, palette buffer, and rendering are all
  headless-tested. A client launched from the palette now runs confined in a Cell (only the
  Wayland socket reaches in, the net namespace is empty, no host data), with the cell
  construction and a connect through the bound socket asserted headlessly. Eye-verify on a
  screen.
- Phase 5 Constellation real-host verification: the whole networking stack that
  can be built and tested on one host is done and in CI, the QUIC + Noise
  transport, serve/sync CLI, concurrent multi-peer serving, mDNS LAN discovery,
  the rendezvous, the relay, and the UDP hole-punch coordination, several of them
  also verified end to end through the binary. What is left needs real hosts
  behind real NATs: proving a hole punch actually traverses one (the coordination
  and the simultaneous open are tested over loopback, but loopback has no NAT to
  cross), seeing which NAT types it opens against, and confirming the relay
  fallback carries the symmetric ones it cannot. Real-host and network work.
- Phase 5 Reconstitution boot/identity wiring: the FIDO2 keyslot model is now done
  (the `identity` crate: an `Authenticator` trait, AEAD keyslots that wrap the same
  master the passphrase derives and the shares split, a `SoftwareAuthenticator` test
  seam, and the real USB-HID `HardwareKey` over `ctap-hid-fido2`'s hmac-secret behind
  the `fido2` feature), with `horizon identity enroll / unlock / reenroll / list`.
  Recovery shares are bound to re-enrollment (`reenroll --share` rebuilds the master
  and seals it for a fresh device), and `unlock` is the unlock path itself (try the
  keyslots, fall back to the passphrase), all headless-tested with the software token
  and verified through the binary; the real key is compile-checked in CI and
  hardware-verified next. The boot integration core is now done too: a cross-platform
  `boot` crate (discover the store, unlock the master by keyslot-then-passphrase, prove
  HEAD) and `horizon boot`, which unlocks once and launches the desktop in-process on
  that master (threaded through `open_broker_with` so the session never re-prompts),
  with `--no-session` as the boot check that runs anywhere; the unlock-and-prove core
  is headless-tested (9 boot + 4 horizon tests) and verified through the binary, and
  the canonical Argon2id KDF now lives once in `boot::derive`. What is left is the
  on-hardware part: eye-verifying a real device boots into its desktop with a touch
  (the DRM session launch), a phone as a post-boot trusted device (a Constellation
  enrollment after boot), and Phase 0 proper (the initramfs/UEFI image this
  orchestration slots into; its init step is now done, see the Phase 0 bullet below).
  Linux for the real key and the desktop; the keyslot core, the secret-sharing core,
  the boot unlock core, and the CLI are cross-platform.
- Phase 0 proper: the actual bootable artifact this orchestration slots into, the real
  "boots anywhere and remembers" demo. Two steps are done. The init (the `init` crate +
  `horizon-init`): the generic initramfs init that assembles the immutable-base +
  writable-overlay root (Home device or Ghost tmpfs), carries the Key's store into the
  new root, and switch_roots into `horizon boot`, with the policy pure and tested
  everywhere and the overlay assembly proven for real in the container. The immutable
  base image (the `keybuild` crate + `horizon-keybuild`): a reproducible squashfs the
  init mounts read-only as the overlay lower, with the build/boot contract (labels, the
  kernel command line) shared with init and the squashfs proven to mount and stack an
  overlay for real in the container. What is left, in order: populate the base with the
  real userland (the horizon + horizon-init binaries and their shared libraries, then
  kernel modules and linux-firmware) so the base actually boots a machine; build the
  persistent data partition (an ext4 with the overlay upper/work and an initialized
  identity store) and prove the whole Key assembles and `horizon boot` opens the store
  on real filesystems (a container loopback integration test, the keystone that ties
  keybuild + init + boot); dm-verity over the base so the immutable layer is
  tamper-evident (a pure-Rust hash tree cross-checked against `veritysetup format`, the
  kernel open eye-verified by booting since this container's kernel lacks
  CONFIG_DM_VERITY); LUKS2 for the Home writable layer and the Ghost read-only store
  handoff, unlocked with the same master the `boot` crate recovers (CONFIG_DM_CRYPT=y
  here, so cryptsetup open is testable in the container); the isohybrid UEFI/BIOS
  bootloader (shim -> systemd-boot/GRUB -> kernel + initramfs) into a bootable Key
  image; and finally booting the whole chain in QEMU (UEFI -> bootloader -> kernel ->
  horizon-init -> horizon boot -> the DRM desktop on virtio-gpu). Environment notes for
  that last stretch: this build container is aarch64 with no KVM, so a shippable x86-64
  Key needs cross-compilation (the `x86_64-unknown-linux-gnu` target plus a kernel,
  busybox, and libs) and QEMU runs in TCG; an aarch64 image booted with
  qemu-system-aarch64 proves the chain on the native ISA short of the x86-64 product.
  Keep build artifacts off the 92%-full `/work` mount (use the container's own fs).
