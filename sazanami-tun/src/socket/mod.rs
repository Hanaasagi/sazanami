#[cfg(target_os = "macos")]
#[path = "darwin.rs"]
pub mod socket;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
pub mod socket;

pub use socket::TunSocket;
