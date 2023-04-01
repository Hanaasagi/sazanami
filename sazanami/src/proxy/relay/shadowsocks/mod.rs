mod digest;
mod tcp;

const BUFFER_SIZE: usize = 8 * 1024; // 8K buffer

pub use tcp::SSTcpStream;

pub use self::digest::bytes_to_key;
