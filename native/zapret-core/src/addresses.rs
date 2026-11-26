use std::{collections::VecDeque, net::SocketAddr};

/// Keep the resolver's preferred family and its order within each family.
/// Apply the connection limit after considering both A and AAAA records.
pub fn connection_addresses(
    addresses: impl IntoIterator<Item = SocketAddr>,
    limit: usize,
) -> Vec<SocketAddr> {
    let mut addresses = addresses.into_iter().peekable();
    let Some(first) = addresses.peek() else {
        return Vec::new();
    };
    let prefer_v6 = first.is_ipv6();
    let mut preferred = VecDeque::new();
    let mut alternate = VecDeque::new();
    for address in addresses {
        let family = if address.is_ipv6() == prefer_v6 {
            &mut preferred
        } else {
            &mut alternate
        };
        if family.len() < limit && !family.contains(&address) {
            family.push_back(address);
        }
        if preferred.len() == limit && alternate.len() == limit {
            break;
        }
    }
    let mut selected = Vec::new();
    while !preferred.is_empty() || !alternate.is_empty() {
        for address in [preferred.pop_front(), alternate.pop_front()]
            .into_iter()
            .flatten()
        {
            selected.push(address);
            if selected.len() == limit {
                return selected;
            }
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn long_dns_answers_preserve_either_fallback_family_and_remove_duplicates() {
        for first_v6 in [true, false] {
            let v4 = |n| SocketAddr::from((Ipv4Addr::new(192, 0, 2, n), 443));
            let v6 = |n| SocketAddr::from((Ipv6Addr::from(u128::from(n)), 443));
            let peers: Vec<_> = (1u8..=48)
                .map(|n| if first_v6 { v6(n) } else { v4(n) })
                .collect();
            let fallback = if first_v6 { v4(1) } else { v6(1) };
            let dns = peers.iter().flat_map(|&p| [p, p]).chain([fallback]);
            let selected = connection_addresses(dns, 16);
            assert_eq!(&selected[..3], &[peers[0], fallback, peers[1]]);
            assert_eq!(selected[2..], peers[1..15]);
            assert_eq!(connection_addresses(peers.clone(), 8), peers[..8]);
        }
    }
}
