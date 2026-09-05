use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub(crate) fn non_public_reason(address: IpAddr) -> Option<&'static str> {
    match address {
        IpAddr::V4(ip) => non_public_v4_reason(ip),
        IpAddr::V6(ip) => non_public_v6_reason(ip),
    }
}

fn non_public_v4_reason(ip: Ipv4Addr) -> Option<&'static str> {
    let octets = ip.octets();
    if ip.is_unspecified() || octets[0] == 0 {
        Some("unspecified or reserved address")
    } else if ip.is_loopback() {
        Some("loopback address")
    } else if ip.is_private() {
        Some("private address")
    } else if ip.is_link_local() {
        Some("link-local address")
    } else if ip.is_multicast() {
        Some("multicast address")
    } else if ip.is_documentation() {
        Some("documentation address")
    } else if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        Some("carrier-grade NAT address")
    } else if (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
    {
        Some("special-purpose address")
    } else if octets[0] >= 240 || ip == Ipv4Addr::BROADCAST {
        Some("reserved address")
    } else {
        None
    }
}

fn non_public_v6_reason(ip: Ipv6Addr) -> Option<&'static str> {
    let segments = ip.segments();
    if ip.is_unspecified() {
        Some("unspecified address")
    } else if ip.is_loopback() {
        Some("loopback address")
    } else if ip.is_multicast() {
        Some("multicast address")
    } else if (segments[0] & 0xfe00) == 0xfc00 {
        Some("unique-local address")
    } else if (segments[0] & 0xffc0) == 0xfe80 {
        Some("link-local address")
    } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        Some("documentation address")
    } else if ip.to_ipv4_mapped().is_some() {
        Some("IPv4-mapped address")
    } else if segments[0] & 0xe000 != 0x2000 {
        Some("non-global unicast address")
    } else {
        None
    }
}

pub(crate) struct ConnectionRateLimiter {
    interval: Duration,
    next: Mutex<tokio::time::Instant>,
}

impl ConnectionRateLimiter {
    pub(crate) fn new(per_second: u32) -> Self {
        Self {
            interval: Duration::from_secs_f64(1.0 / f64::from(per_second)),
            next: Mutex::new(tokio::time::Instant::now()),
        }
    }

    pub(crate) async fn wait(&self, cancel: &CancellationToken) -> Result<(), ()> {
        let scheduled = {
            let mut next = self.next.lock().await;
            let scheduled = (*next).max(tokio::time::Instant::now());
            *next = scheduled + self.interval;
            scheduled
        };
        tokio::select! {
            _ = cancel.cancelled() => Err(()),
            _ = tokio::time::sleep_until(scheduled) => Ok(()),
        }
    }
}
