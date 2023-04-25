use std::net::Ipv4Addr;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use anyhow::Result;
use bit_set::BitSet;

/// IPv4 pool
pub struct IPv4Pool {
    start_ip: Ipv4Addr,
    end_ip: Ipv4Addr,
    pool_range: (u32, u32),
    // Next IP
    offset: AtomicUsize,
    allocated_ip: BitSet,
    pool_size: usize,
    reclaimed_ip: BitSet,
}

impl IPv4Pool {
    /// Create a new IPv4Pool
    pub fn new(start_ip: Ipv4Addr, end_ip: Ipv4Addr) -> Self {
        let offset = AtomicUsize::new(0);
        let pool_range = (start_ip.into(), end_ip.into());
        let pool_size = (pool_range.1 - pool_range.0 + 1) as usize;

        Self {
            start_ip,
            end_ip,
            offset,
            pool_range,
            allocated_ip: BitSet::with_capacity(pool_size),
            pool_size,
            reclaimed_ip: BitSet::with_capacity(pool_size),
        }
    }

    #[inline]
    fn range_start(&self) -> u32 {
        self.pool_range.0
    }

    #[allow(unused)]
    #[inline]
    fn range_end(&self) -> u32 {
        self.pool_range.1
    }

    #[inline]
    pub fn start_ip(&self) -> Ipv4Addr {
        self.start_ip
    }

    #[inline]
    pub fn end_ip(&self) -> Ipv4Addr {
        self.end_ip
    }

    #[inline]
    pub fn allocated_count(&self) -> usize {
        self.allocated_ip.len()
    }

    pub fn is_allocated(&self, ip: Ipv4Addr) -> bool {
        let ip: u32 = ip.into();
        let ip_offset: u32 = ip - self.range_start();

        self.allocated_ip.contains(ip_offset as usize)
    }

    pub fn iter_allocated_ip(&self) -> Box<dyn Iterator<Item = Ipv4Addr> + '_> {
        Box::new(
            self.allocated_ip
                .iter()
                .map(|x| Ipv4Addr::from(x as u32 + self.range_start())),
        )
    }

    /// Allocate a free ip
    pub fn allocate_ip(&mut self) -> Result<Ipv4Addr> {
        // fast way
        if !self.reclaimed_ip.is_empty() {
            let ip_offset = self.reclaimed_ip.iter().next().unwrap();

            self.reclaimed_ip.remove(ip_offset);
            self.allocated_ip.insert(ip_offset);

            return Ok(Ipv4Addr::from(ip_offset as u32 + self.range_start()));
        }

        loop {
            if self.allocated_ip.len() == self.pool_size {
                return Err(anyhow::anyhow!("IP pool is full"));
            }

            let ip_offset = self.offset.fetch_add(1, Ordering::SeqCst);
            // reset
            if ip_offset >= self.pool_size {
                *self.offset.get_mut() = 0;
                continue;
            }

            if !self.allocated_ip.contains(ip_offset) {
                self.allocated_ip.insert(ip_offset);
                return Ok(Ipv4Addr::from(ip_offset as u32 + self.range_start()));
            }
        }
    }

    pub fn release_ip(&mut self, ip: Ipv4Addr) {
        let ip: u32 = ip.into();
        let ip_offset: u32 = ip - self.range_start();

        // mark this ip is reclaimed
        self.reclaimed_ip.insert(ip_offset as usize);
        // mark this ip unallocated
        self.allocated_ip.remove(ip_offset as usize);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allocate_ip() {
        let mut ip_pool = IPv4Pool::new(
            Ipv4Addr::new(192, 168, 0, 122),
            Ipv4Addr::new(192, 168, 0, 125),
        );

        assert!(!ip_pool.is_allocated(Ipv4Addr::new(192, 168, 0, 122)));
        assert_eq!(
            ip_pool.allocate_ip().unwrap(),
            Ipv4Addr::new(192, 168, 0, 122)
        );
        assert!(ip_pool.is_allocated(Ipv4Addr::new(192, 168, 0, 122)));

        assert_eq!(
            ip_pool.allocate_ip().unwrap(),
            Ipv4Addr::new(192, 168, 0, 123)
        );
        assert_eq!(
            ip_pool.allocate_ip().unwrap(),
            Ipv4Addr::new(192, 168, 0, 124)
        );
        assert_eq!(
            ip_pool.allocate_ip().unwrap(),
            Ipv4Addr::new(192, 168, 0, 125)
        );

        assert_eq!(ip_pool.allocated_count(), 4);
    }

    #[test]
    fn test_allocate_ip_when_full() {
        let mut ip_pool = IPv4Pool::new(
            Ipv4Addr::new(192, 168, 0, 122),
            Ipv4Addr::new(192, 168, 0, 125),
        );
        for _ in 0..4 {
            ip_pool.allocate_ip().unwrap();
        }
        // full
        assert!(ip_pool.allocate_ip().is_err());
    }
    #[test]
    fn test_iter_allocated_ip() {
        let mut ip_pool = IPv4Pool::new(
            Ipv4Addr::new(192, 168, 0, 122),
            Ipv4Addr::new(192, 168, 0, 125),
        );
        for _ in 0..4 {
            ip_pool.allocate_ip().unwrap();
        }

        let ips: Vec<Ipv4Addr> = ip_pool.iter_allocated_ip().collect();
        assert_eq!(ips.len(), 4);
        assert_eq!(
            ips,
            vec![
                Ipv4Addr::new(192, 168, 0, 122),
                Ipv4Addr::new(192, 168, 0, 123),
                Ipv4Addr::new(192, 168, 0, 124),
                Ipv4Addr::new(192, 168, 0, 125),
            ]
        );
    }

    #[test]
    fn test_release_ip() {
        let mut ip_pool = IPv4Pool::new(
            Ipv4Addr::new(192, 168, 0, 122),
            Ipv4Addr::new(192, 168, 0, 125),
        );
        for _ in 0..4 {
            ip_pool.allocate_ip().unwrap();
        }
        // full
        assert!(ip_pool.allocate_ip().is_err());
        // release
        assert!(ip_pool.is_allocated(Ipv4Addr::new(192, 168, 0, 122)));
        ip_pool.release_ip(Ipv4Addr::new(192, 168, 0, 122));
        assert!(!ip_pool.is_allocated(Ipv4Addr::new(192, 168, 0, 122)));
        assert_eq!(ip_pool.allocated_count(), 3);
        assert_eq!(
            ip_pool.allocate_ip().unwrap(),
            Ipv4Addr::new(192, 168, 0, 122)
        );

        ip_pool.release_ip(Ipv4Addr::new(192, 168, 0, 123));
        ip_pool.release_ip(Ipv4Addr::new(192, 168, 0, 125));

        assert_eq!(ip_pool.allocated_count(), 2);
        assert_eq!(
            ip_pool.allocate_ip().unwrap(),
            Ipv4Addr::new(192, 168, 0, 123)
        );
        assert_eq!(
            ip_pool.allocate_ip().unwrap(),
            Ipv4Addr::new(192, 168, 0, 125)
        );
        assert_eq!(ip_pool.allocated_count(), 4);
    }
}
