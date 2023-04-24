use std::hash::Hash;
use std::hash::Hasher;
#[allow(deprecated)]
use std::hash::SipHasher13;

use rand::RngCore;

use super::Node;

pub struct JumpHasher<N: Node> {
    nodes: Vec<N>,
    k1: u64,
    k2: u64,
}

impl<N: Node> JumpHasher<N> {
    /// Create a JumpHasher
    pub fn new() -> JumpHasher<N> {
        let mut rng = rand::thread_rng();
        Self::new_with_keys(rng.next_u64(), rng.next_u64())
    }

    pub fn new_with_keys(k1: u64, k2: u64) -> JumpHasher<N> {
        Self {
            nodes: Vec::new(),
            k1,
            k2,
        }
    }
    /// Add a new node
    pub fn add(&mut self, node: &N) {
        self.nodes.push(node.clone())
    }

    /// Get a node by key. Return `None` if no valid node inside
    pub fn get<'a>(&'a self, key: &[u8]) -> Option<&'a N> {
        if self.nodes.is_empty() {
            return None;
        }
        let slot = self.slot(&key, self.nodes.len() as u32) as usize;

        self.nodes.get(slot)
    }

    /// Get a node by string key
    pub fn get_str<'a>(&'a self, key: &str) -> Option<&'a N> {
        self.get(key.as_bytes())
    }

    /// Get a node by key. Return `None` if no valid node inside
    pub fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<&'a mut N> {
        if self.nodes.is_empty() {
            return None;
        }
        let slot = self.slot(&key, self.nodes.len() as u32) as usize;

        self.nodes.get_mut(slot)
    }

    /// Get a node by string key
    pub fn get_str_mut<'a>(&'a mut self, key: &str) -> Option<&'a mut N> {
        self.get_mut(key.as_bytes())
    }

    /// Number of nodes
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a slot for the key `key`, out of `slot_count` available slots.
    fn slot<T: Hash>(&self, key: &T, slot_count: u32) -> u32 {
        #[allow(deprecated)]
        let mut hs = SipHasher13::new_with_keys(self.k1, self.k2);
        key.hash(&mut hs);
        let mut h = hs.finish();
        let (mut b, mut j) = (-1i64, 0i64);
        while j < slot_count as i64 {
            b = j;
            h = h.wrapping_mul(2862933555777941757).wrapping_add(1);
            j = ((b.wrapping_add(1) as f64) * (((1u64 << 31) as f64) / (((h >> 33) + 1) as f64)))
                as i64;
        }
        b as u32
    }
}

impl<N: Node> Default for JumpHasher<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[derive(Debug, Clone, Eq, PartialEq)]
    struct ServerNode {
        host: String,
        port: u16,
    }

    impl Node for ServerNode {
        fn hash_key(&self) -> String {
            format!("{}:{}", self.host, self.port)
        }
    }

    impl ServerNode {
        fn new(host: &str, port: u16) -> ServerNode {
            ServerNode {
                host: host.to_owned(),
                port,
            }
        }
    }

    #[test]
    fn test_basic() {
        let mut j = JumpHasher::<ServerNode>::new_with_keys(0, 0);

        let nodes = [
            ServerNode::new("localhost", 12345),
            ServerNode::new("localhost", 12346),
        ];

        for node in nodes.iter() {
            j.add(node);
        }

        let node = j.get_str("hello").unwrap().clone();
        assert_eq!(node, ServerNode::new("localhost", 12345));
        let node = j.get_str("hello2222").unwrap().clone();
        // different node
        assert_eq!(node, ServerNode::new("localhost", 12346));

        // insert a new node
        let node = ServerNode::new("localhost", 12347);
        j.add(&node);

        // not changed
        let node = j.get_str("hello").unwrap().clone();
        assert_eq!(node, ServerNode::new("localhost", 12345));

        // insert again
        let nodes = [
            ServerNode::new("localhost", 12348),
            ServerNode::new("localhost", 12349),
            ServerNode::new("localhost", 12350),
            ServerNode::new("localhost", 12351),
            ServerNode::new("localhost", 12352),
            ServerNode::new("localhost", 12353),
        ];
        for node in nodes.iter() {
            j.add(node);
        }

        // changed
        let node = j.get_str("hello").unwrap().clone();
        assert_eq!(node, ServerNode::new("localhost", 12352));
    }

    #[test]
    fn get_from_empty() {
        let mut j = JumpHasher::<ServerNode>::new();
        assert_eq!(j.get_str(""), None);
        assert_eq!(j.get_str_mut(""), None);
    }
}
