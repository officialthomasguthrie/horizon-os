//! mDNS LAN discovery for the Constellation.
//!
//! A network sync needs a host:port. On a LAN you usually do not have one: you
//! just want "the other device of this identity that is serving right now". This
//! module announces a serving peer and finds peers over multicast DNS (DNS-SD),
//! so a sync can locate one with nothing typed in.
//!
//! What is advertised is a non-secret rendezvous label: a short fingerprint
//! derived one-way from the identity master, under its own domain separator, so
//! it leaks neither the master nor any other key derived from it (the Lifestream
//! keys, the Noise PSK). The fingerprint only says "a device of identity X is
//! here"; it grants nothing. Authentication is still the Noise NNpsk0 handshake
//! at connect time (see [`super::net`]): a peer that reads the fingerprint, or
//! lists every fingerprint on the wire, still cannot complete the handshake or
//! open an object without the master. So the fingerprint is safe to broadcast,
//! and discovery never widens what an attacker on the same network can do.
//!
//! This is LAN-only: multicast does not cross subnets. Finding peers across the
//! open internet (a rendezvous or relay) and punching through NAT are separate
//! problems that need real hosts.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::error::{Error, Result};
use crate::label::fingerprint;

// RFC 6763 caps the service-name label at 15 bytes, so the type is abbreviated
// (horizon-cstl, 12). UDP because the link underneath it is QUIC.
const SERVICE_TYPE: &str = "_horizon-cstl._udp.local.";
// TXT key carrying the identity fingerprint peers match on.
const FP_KEY: &str = "fp";

// A live mDNS announcement that this device serves `master`'s identity on a
// port. Hold it for as long as you serve; dropping it withdraws the
// announcement.
pub struct Beacon {
    daemon: ServiceDaemon,
    fullname: String,
}

impl Beacon {
    // Announce that this host serves `master` on `port`. The daemon fills in the
    // host's own LAN addresses (enable_addr_auto), so a peer that matches the
    // fingerprint learns where to dial.
    pub fn announce(master: &[u8; 32], port: u16) -> Result<Beacon> {
        let daemon = ServiceDaemon::new().map_err(err)?;

        // The instance and host names only need to be unique on the LAN; the pid
        // keeps two devices of one identity from clashing on them. Peers match on
        // the fp TXT entry, not on these names.
        let pid = std::process::id();
        let instance = format!("horizon-{pid}");
        let host = format!("horizon-{pid}.local.");

        let mut props = HashMap::new();
        props.insert(FP_KEY.to_string(), fingerprint(master));

        let info = ServiceInfo::new(SERVICE_TYPE, &instance, &host, (), port, props)
            .map_err(err)?
            .enable_addr_auto();
        let fullname = info.get_fullname().to_string();
        daemon.register(info).map_err(err)?;
        Ok(Beacon { daemon, fullname })
    }
}

impl Drop for Beacon {
    fn drop(&mut self) {
        // Best effort: pull the announcement back, then stop the daemon.
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}

// Find peers serving `master`'s identity on the LAN, gathering for up to
// `timeout`. Returns the socket addresses to dial, sorted and deduplicated. A
// host that is also announcing may resolve itself; the caller decides what to do
// with that.
pub fn discover(master: &[u8; 32], timeout: Duration) -> Result<Vec<SocketAddr>> {
    let want = fingerprint(master);
    let daemon = ServiceDaemon::new().map_err(err)?;
    let rx = daemon.browse(SERVICE_TYPE).map_err(err)?;

    let deadline = Instant::now() + timeout;
    let mut found = std::collections::HashSet::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match rx.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if info.get_property_val_str(FP_KEY) == Some(want.as_str()) {
                    let port = info.get_port();
                    for ip in info.get_addresses_v4() {
                        found.insert(SocketAddr::new(IpAddr::V4(ip), port));
                    }
                }
            }
            Ok(_) => {}
            // Timeout (deadline reached) or the daemon went away: stop waiting.
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();

    let mut addrs: Vec<SocketAddr> = found.into_iter().collect();
    addrs.sort();
    Ok(addrs)
}

fn err(e: impl std::fmt::Display) -> Error {
    Error::Net(e.to_string())
}
