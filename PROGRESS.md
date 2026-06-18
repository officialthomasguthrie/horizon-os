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
  and compile-checked on the same split, so it too is waiting on that eye part;
  what is left on it is a display-only secondary GPU and a real multi-monitor
  logical layout. Then the shell proper: the compositor draws the Glass surface
  (already a pure Model -> Scene -> Pixmap renderer in the `glass` crate) as the
  L5 desktop over the weave audit log, with the Aura intent line as launcher and
  command palette. Confined cells can already host compositor surfaces (the cells
  exec path is ready). Linux-only.
- Glass: the live transparency surface over the weave audit log. The model layer
  and the drawn surface are both done (the `glass` crate: a pure fold of the
  broker's grant table and audit log into a per-principal map of
  live/severed/blocked channels, a 7-day timeline, and the sever kill switch, then
  `surface::layout` + `raster::rasterize` turning that Model into an RGBA Pixmap
  with hit targets, all headless-testable and CI-green on darwin), with a text
  report (`horizon glass show`) and an image render (`horizon glass render`) as the
  headless stand-ins and `horizon glass sever` as the kill switch. What is left is
  the compositor blit: upload the Pixmap as a texture and draw it as the shell
  background under client windows, then route a click on a `sever` hit target back
  through `Glass::sever`. That lands with the `render`/`winit`/`udev` features and a
  screen to verify it on; a confined cell can host it (the cells exec path is
  ready).
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
