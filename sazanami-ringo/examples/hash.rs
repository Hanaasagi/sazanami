use md5::Md5;
use sazanami_ringo::HashRing;
use sazanami_ringo::JumpHasher;
use sazanami_ringo::Node;

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

fn show_hash_ring_usage() {
    let nodes = [
        ServerNode::new("localhost", 12345),
        ServerNode::new("localhost", 12346),
        ServerNode::new("localhost", 12347),
        ServerNode::new("localhost", 12348),
        ServerNode::new("localhost", 12349),
        ServerNode::new("localhost", 12350),
    ];

    let mut ring: HashRing<_, Md5> = HashRing::new();

    for node in nodes.iter() {
        ring.add(node, 1);
    }

    assert_eq!(ring.len(), nodes.len());

    let hello_node = ring.get_str("hello").unwrap().clone();
    assert_eq!(hello_node, ServerNode::new("localhost", 12345));

    ring.add(&ServerNode::new("localhost", 12351), 1);
    assert_eq!(ring.get_str("hello").unwrap().clone(), hello_node);

    ring.remove(&ServerNode::new("localhost", 12350));
    assert_eq!(ring.get_str("hello").unwrap().clone(), hello_node);
}

fn show_jump_hash_usage() {
    let mut hasher = JumpHasher::<ServerNode>::new_with_keys(0, 0);

    let nodes = [
        ServerNode::new("localhost", 12345),
        ServerNode::new("localhost", 12346),
    ];

    for node in nodes.iter() {
        hasher.add(node);
    }

    let node = hasher.get_str("hello").unwrap().clone();
    assert_eq!(node, ServerNode::new("localhost", 12345));
    let node = hasher.get_str("hello2222").unwrap().clone();
    // different node
    assert_eq!(node, ServerNode::new("localhost", 12346));

    // insert a new node
    let node = ServerNode::new("localhost", 12347);
    hasher.add(&node);

    // not changed
    let node = hasher.get_str("hello").unwrap().clone();
    assert_eq!(node, ServerNode::new("localhost", 12345));
}

fn main() {
    show_hash_ring_usage();
    show_jump_hash_usage();
}
