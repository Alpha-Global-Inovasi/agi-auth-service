//! The client's address behind reverse proxies.

use actix_web::HttpRequest;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Reverse proxies whose `X-Forwarded-For` header is believed: addresses and CIDR
/// networks, such as `10.0.0.0/8, 192.168.1.5, ::1`.
///
/// Without any (the default), the client address is the TCP peer. With some, a request
/// from a trusted peer has its `X-Forwarded-For` read from the right: trusted proxies
/// are skipped and the first other address is the client. An entry that is not an IP
/// address stops the walk, since it cannot be checked. This is the same rule as
/// `TRUSTED_PROXIES` in `rusted-telemetry`, so both see the same client.
///
/// Actix's `ConnectionInfo::realip_remote_addr` is not used: it believes the header
/// from anyone, so any client could pick the address its rate limit is counted under.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrustedProxies(Vec<Network>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            _ => false,
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = usize::from(prefix / 8);
    let rest = prefix % 8;
    if a[..full] != b[..full] {
        return false;
    }
    if rest == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rest);
    (a[full] & mask) == (b[full] & mask)
}

impl TrustedProxies {
    /// No trusted proxy: the client is always the TCP peer.
    pub fn none() -> Self {
        Self::default()
    }

    /// Whether no proxy is trusted.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether `ip` is one of the trusted proxies.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = ip.to_canonical();
        self.0.iter().any(|net| net.contains(ip))
    }

    /// The client address of a request from `peer` that carries `forwarded_for`
    /// (the `X-Forwarded-For` value).
    pub fn client_ip(&self, peer: Option<IpAddr>, forwarded_for: Option<&str>) -> Option<IpAddr> {
        let peer = peer?.to_canonical();
        if !self.contains(peer) {
            return Some(peer);
        }
        let mut client = peer;
        for entry in forwarded_for.unwrap_or("").rsplit(',') {
            let Ok(ip) = entry.trim().parse::<IpAddr>() else {
                break;
            };
            client = ip.to_canonical();
            if !self.contains(client) {
                break;
            }
        }
        Some(client)
    }

    /// The client address of `req`.
    pub fn client_ip_of(&self, req: &HttpRequest) -> Option<IpAddr> {
        let peer = req.peer_addr().map(|addr| addr.ip());
        if self.is_empty() {
            return peer.map(|ip| ip.to_canonical());
        }
        // Several headers are joined, as if they were one list.
        let forwarded: Vec<&str> = req
            .headers()
            .get_all("x-forwarded-for")
            .filter_map(|value| value.to_str().ok())
            .collect();
        let forwarded = forwarded.join(",");
        self.client_ip(peer, Some(&forwarded))
    }
}

/// Error from parsing [`TrustedProxies`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidProxy(String);

impl fmt::Display for InvalidProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "`{}` is not an IP address or CIDR network", self.0)
    }
}

impl std::error::Error for InvalidProxy {}

impl FromStr for TrustedProxies {
    type Err = InvalidProxy;

    /// Parses a comma-separated list of IP addresses and CIDR networks.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(|entry| parse_network(entry).ok_or_else(|| InvalidProxy(entry.to_owned())))
            .collect::<Result<_, _>>()
            .map(TrustedProxies)
    }
}

fn parse_network(entry: &str) -> Option<Network> {
    let (address, prefix) = match entry.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (entry, None),
    };
    let address = address.parse::<IpAddr>().ok()?.to_canonical();
    let max = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix.parse::<u8>().ok().filter(|p| *p <= max)?,
        None => max,
    };
    // An IPv4-mapped network written in IPv6 form becomes an IPv4 network.
    let prefix = match (entry.contains(':'), address) {
        (true, IpAddr::V4(_)) => prefix.checked_sub(96)?,
        _ => prefix,
    };
    Some(Network { address, prefix })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_addresses_and_networks() {
        let proxies: TrustedProxies = "10.0.0.0/8, 192.168.1.5,::1, fd00::/16".parse().unwrap();
        assert!(proxies.contains(ip("10.20.30.40")));
        assert!(proxies.contains(ip("192.168.1.5")));
        assert!(!proxies.contains(ip("192.168.1.6")));
        assert!(proxies.contains(ip("::1")));
        assert!(proxies.contains(ip("::ffff:10.0.0.1")));
        assert!(proxies.contains(ip("fd00:1::2")));
        assert!(!proxies.contains(ip("fd01::2")));
        assert!("".parse::<TrustedProxies>().unwrap().is_empty());
        assert!("10.0.0.0/33".parse::<TrustedProxies>().is_err());
        assert!("proxy.internal".parse::<TrustedProxies>().is_err());
        let partial: TrustedProxies = "10.1.128.0/17".parse().unwrap();
        assert!(partial.contains(ip("10.1.200.1")));
        assert!(!partial.contains(ip("10.1.100.1")));
    }

    #[test]
    fn forwarded_for_is_ignored_from_untrusted_peers() {
        let proxies: TrustedProxies = "10.0.0.0/8".parse().unwrap();
        let client = proxies.client_ip(Some(ip("203.0.113.9")), Some("198.51.100.1"));
        assert_eq!(client, Some(ip("203.0.113.9")));
        assert_eq!(
            TrustedProxies::none().client_ip(Some(ip("10.0.0.1")), Some("198.51.100.1")),
            Some(ip("10.0.0.1"))
        );
    }

    #[test]
    fn forwarded_for_is_read_from_the_right_past_trusted_proxies() {
        let proxies: TrustedProxies = "10.0.0.0/8".parse().unwrap();
        let peer = Some(ip("10.0.0.2"));
        // The left-most entry was written by the client and is not believed.
        let header = "1.2.3.4, 198.51.100.7, 10.0.0.9";
        assert_eq!(
            proxies.client_ip(peer, Some(header)),
            Some(ip("198.51.100.7"))
        );
        assert_eq!(
            proxies.client_ip(peer, Some("garbage, 10.0.0.3")),
            Some(ip("10.0.0.3"))
        );
        assert_eq!(proxies.client_ip(peer, None), peer);
    }
}
