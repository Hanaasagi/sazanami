use std::collections::{BTreeMap, HashMap};
use std::marker;

use digest::Digest;

use super::Node;

#[derive(Clone)]
pub struct HashRing<N: Node, D: Digest> {
    ring: BTreeMap<Vec<u8>, N>,
    replicas: HashMap<String, usize>,
    _phantom: marker::PhantomData<D>,
}

impl<N: Node, D: Digest> HashRing<N, D> {
    /// Create a Hash Ring
    pub fn new() -> HashRing<N, D> {
        Self {
            ring: BTreeMap::new(),
            replicas: HashMap::new(),
            _phantom: marker::PhantomData,
        }
    }

    /// Compute hash
    fn get_hash<T: AsRef<[u8]>>(key: T) -> Vec<u8> {
        D::digest(key).to_vec()
    }

    /// Add a new node
    pub fn add(&mut self, node: &N, num_replicas: usize) {
        let hash_key = node.hash_key();

        self.remove(node);

        self.replicas.insert(hash_key.clone(), num_replicas);
        for replica in 0..num_replicas {
            let node_ident = format!("{hash_key}:{replica}");
            let key = Self::get_hash(node_ident.as_bytes());

            self.ring.insert(key, node.clone());
        }
    }

    /// Get a node by key. Return `None` if no valid node inside
    pub fn get<'a>(&'a self, key: &[u8]) -> Option<&'a N> {
        if self.ring.is_empty() {
            return None;
        }

        let hashed_key = Self::get_hash(key);

        let entry = self.ring.range(hashed_key..).next();
        if let Some((_k, v)) = entry {
            return Some(v);
        }

        // Back to the first one
        let first = self.ring.iter().next();
        let (_k, v) = first.unwrap();
        Some(v)
    }

    /// Get a node by string key
    pub fn get_str<'a>(&'a self, key: &str) -> Option<&'a N> {
        self.get(key.as_bytes())
    }

    /// Get a node by key. Return `None` if no valid node inside
    pub fn get_mut<'a>(&'a mut self, key: &[u8]) -> Option<&'a mut N> {
        let hashed_key = self.get_node_hashed_key(key);
        hashed_key.and_then(move |k| self.ring.get_mut(&k))
    }

    // Get a node's hashed key by key. Return `None` if no valid node inside
    fn get_node_hashed_key(&self, key: &[u8]) -> Option<Vec<u8>> {
        if self.ring.is_empty() {
            return None;
        }

        let hashed_key = Self::get_hash(key);

        let entry = self.ring.range(hashed_key..).next();
        if let Some((k, _v)) = entry {
            return Some(k.clone());
        }

        // Back to the first one
        let first = self.ring.iter().next();
        let (k, _v) = first.unwrap();
        Some(k.clone())
    }

    /// Get a node by string key
    pub fn get_str_mut<'a>(&'a mut self, key: &str) -> Option<&'a mut N> {
        self.get_mut(key.as_bytes())
    }

    /// Remove a node with all replicas (virtual nodes)
    pub fn remove(&mut self, node: &N) {
        let node_name = node.hash_key();

        let num_replicas = match self.replicas.remove(&node_name) {
            Some(val) => val,
            None => {
                return;
            }
        };

        for replica in 0..num_replicas {
            let hash_key = node.hash_key();
            let node_ident = format!("{hash_key}:{replica}");
            let key = Self::get_hash(node_ident.as_bytes());
            self.ring.remove(&key);
        }
    }

    /// Number of nodes
    pub fn len(&self) -> usize {
        self.ring.len()
    }

    /// Is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<N: Node, D: Digest> Default for HashRing<N, D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use md5::Md5;

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
        let nodes = [
            ServerNode::new("localhost", 12345),
            ServerNode::new("localhost", 12346),
            ServerNode::new("localhost", 12347),
            ServerNode::new("localhost", 12348),
            ServerNode::new("localhost", 12349),
            ServerNode::new("localhost", 12350),
            ServerNode::new("localhost", 12351),
            ServerNode::new("localhost", 12352),
            ServerNode::new("localhost", 12353),
        ];

        const REPLICAS: usize = 20;

        let mut hr: HashRing<_, Md5> = HashRing::new();

        for node in nodes.iter() {
            hr.add(node, REPLICAS);
        }

        assert_eq!(hr.len(), nodes.len() * REPLICAS);

        let node_for_hello = hr.get_str("hello").unwrap().clone();
        assert_eq!(node_for_hello, ServerNode::new("localhost", 12347));

        hr.remove(&ServerNode::new("localhost", 12350));
        assert_eq!(hr.get_str("hello").unwrap().clone(), node_for_hello);

        assert_eq!(hr.len(), (nodes.len() - 1) * REPLICAS);

        hr.remove(&ServerNode::new("localhost", 12347));
        assert_ne!(hr.get_str("hello").unwrap().clone(), node_for_hello);

        assert_eq!(hr.len(), (nodes.len() - 2) * REPLICAS);
    }

    #[test]
    fn get_from_empty() {
        let mut hr = HashRing::<ServerNode, Md5>::new();
        assert_eq!(hr.get_str(""), None);
        assert_eq!(hr.get_str_mut(""), None);
    }
}
