//! Client IP extraction from proxy headers (`core/src/utils/ip.ts`).

use std::net::{IpAddr, Ipv6Addr};

use http::HeaderMap;

#[derive(Debug, Clone)]
pub struct IpConfig {
    /// Headers to read, in order. Defaults to `["x-forwarded-for"]`.
    pub headers: Vec<String>,
    pub disable_tracking: bool,
    /// IPv6 addresses are truncated to this prefix length (default 64).
    pub ipv6_subnet: u8,
    /// CIDRs of trusted proxies. When set, the right-most untrusted hop is used;
    /// otherwise the header must contain exactly one address.
    pub trusted_proxies: Vec<String>,
    /// Fall back to `127.0.0.1` when no IP is found (development/test).
    pub localhost_fallback: bool,
}

impl Default for IpConfig {
    fn default() -> Self {
        Self {
            headers: vec!["x-forwarded-for".into()],
            disable_tracking: false,
            ipv6_subnet: 64,
            trusted_proxies: vec![],
            localhost_fallback: false,
        }
    }
}

fn mapped_v4(ip: &Ipv6Addr) -> Option<IpAddr> {
    ip.to_ipv4_mapped().map(IpAddr::V4)
}

fn bytes_of(ip: &IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.octets().to_vec(),
            None => v6.octets().to_vec(),
        },
    }
}

/// Normalize an address: lowercase, unwrap IPv4-mapped IPv6, mask IPv6 to `subnet` bits
/// and print the IPv6 form fully expanded.
pub fn normalize_ip(ip: &str, ipv6_subnet: u8) -> String {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.to_string(),
        Ok(IpAddr::V6(v6)) => {
            if let Some(v4) = mapped_v4(&v6) {
                return v4.to_string();
            }
            let mut segments = v6.segments();
            if ipv6_subnet < 128 {
                let mut bits = ipv6_subnet as i32;
                for seg in segments.iter_mut() {
                    if bits <= 0 {
                        *seg = 0;
                    } else if bits < 16 {
                        *seg &= (0xffffu32 << (16 - bits)) as u16;
                        bits = 0;
                    } else {
                        bits -= 16;
                    }
                }
            }
            segments.iter().map(|s| format!("{s:04x}")).collect::<Vec<_>>().join(":")
        }
        Err(_) => ip.to_lowercase(),
    }
}

fn parse_cidr(value: &str) -> Option<(Vec<u8>, u32)> {
    let (addr, prefix) = match value.rsplit_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (value, None),
    };
    let bytes = bytes_of(&addr.parse::<IpAddr>().ok()?);
    let max = bytes.len() as u32 * 8;
    let prefix = match prefix {
        Some(p) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => p.parse().ok()?,
        Some(_) => return None,
        None => max,
    };
    (prefix <= max).then_some((bytes, prefix))
}

fn matches_cidr(ip: &[u8], net: &(Vec<u8>, u32)) -> bool {
    if ip.len() != net.0.len() {
        return false;
    }
    let mut bits = net.1 as i32;
    for (a, b) in ip.iter().zip(&net.0) {
        if bits <= 0 {
            break;
        }
        let take = bits.min(8);
        let mask = if take == 8 { 0xff } else { (0xffu32 << (8 - take)) as u8 };
        if a & mask != b & mask {
            return false;
        }
        bits -= 8;
    }
    true
}

pub fn get_ip_from_header(value: &str, config: &IpConfig) -> Option<String> {
    let ips: Vec<&str> = value.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
    if ips.is_empty() {
        return None;
    }
    let proxies: Vec<_> = config.trusted_proxies.iter().filter_map(|p| parse_cidr(p)).collect();
    if !proxies.is_empty() {
        for ip in ips.iter().rev() {
            let bytes = bytes_of(&ip.parse::<IpAddr>().ok()?);
            if proxies.iter().any(|p| matches_cidr(&bytes, p)) {
                continue;
            }
            return Some(normalize_ip(ip, config.ipv6_subnet));
        }
        return None;
    }
    if ips.len() != 1 || ips[0].parse::<IpAddr>().is_err() {
        return None;
    }
    Some(normalize_ip(ips[0], config.ipv6_subnet))
}

pub fn get_ip(headers: &HeaderMap, config: &IpConfig) -> Option<String> {
    if config.disable_tracking {
        return None;
    }
    for name in &config.headers {
        if let Some(v) = headers.get(name.as_str()).and_then(|v| v.to_str().ok())
            && let Some(ip) = get_ip_from_header(v, config)
        {
            return Some(ip);
        }
    }
    config.localhost_fallback.then(|| "127.0.0.1".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(normalize_ip("::ffff:192.168.1.1", 64), "192.168.1.1");
        assert_eq!(normalize_ip("2001:db8::1", 64), "2001:0db8:0000:0000:0000:0000:0000:0000");
        assert_eq!(normalize_ip("2001:db8::1", 128), "2001:0db8:0000:0000:0000:0000:0000:0001");
    }

    #[test]
    fn header_rules() {
        let c = IpConfig::default();
        assert_eq!(get_ip_from_header("1.2.3.4", &c).as_deref(), Some("1.2.3.4"));
        assert_eq!(get_ip_from_header("1.2.3.4, 5.6.7.8", &c), None);
        let c = IpConfig { trusted_proxies: vec!["10.0.0.0/8".into()], ..Default::default() };
        assert_eq!(get_ip_from_header("1.2.3.4, 5.6.7.8, 10.1.1.1", &c).as_deref(), Some("5.6.7.8"));
    }
}
