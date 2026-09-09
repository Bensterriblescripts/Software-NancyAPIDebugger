use std::net::IpAddr;
use std::sync::OnceLock;

#[derive(serde::Deserialize)]
struct AddressRanges {
    ipv4: Vec<String>,
    ipv6: Vec<String>,
}

pub(crate) fn is_cloudflare_address(ip: IpAddr) -> bool {
    static RANGES: OnceLock<Vec<(IpAddr, u32)>> = OnceLock::new();
    let ranges = RANGES.get_or_init(|| {
        let snapshot: AddressRanges =
            serde_json::from_str(include_str!("cloudflare_ip_ranges.json"))
                .expect("valid bundled Cloudflare address ranges");
        snapshot
            .ipv4
            .into_iter()
            .chain(snapshot.ipv6)
            .map(|cidr| {
                let (network, prefix) = cidr.split_once('/').expect("bundled CIDR prefix");
                let network: IpAddr = network.parse().expect("bundled network address");
                let prefix: u32 = prefix.parse().expect("bundled network prefix");
                assert!(prefix <= if network.is_ipv4() { 32 } else { 128 });
                (network, prefix)
            })
            .collect()
    });
    let ip = ip.to_canonical();
    ranges.iter().any(|&(network, prefix)| match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(network)) => {
            let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
            u32::from(ip) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(ip), IpAddr::V6(network)) => {
            let mask = u128::MAX.checked_shl(128 - prefix).unwrap_or(0);
            u128::from(ip) & mask == u128::from(network) & mask
        }
        _ => false,
    })
}
