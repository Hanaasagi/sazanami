#[cfg(target_os = "macos")]
#[path = "darwin.rs"]
#[allow(clippy::module_inception)]
pub mod socket;

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
#[allow(clippy::module_inception)]
pub mod socket;

pub use socket::TunSocket;
