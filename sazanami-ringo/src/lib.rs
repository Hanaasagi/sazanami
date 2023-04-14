#![feature(hashmap_internals)]
mod jump;
mod karger;

pub trait Node: Clone {
    fn hash_key(&self) -> String;
}

pub use jump::JumpHasher;
pub use karger::HashRing;
