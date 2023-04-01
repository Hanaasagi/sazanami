#![no_std]

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockHashKey {
    pub sip4: u32,  // 源 IP
    pub dip4: u32,  // 目的 IP
    pub family: u8, // 协议类型
    pub pad1: u8,   // this padding required for 64bit alignment
    pub pad2: u16,  // else ebpf kernel verifier rejects loading of the program
    pub pad3: u32,
    pub sport: u32, // 源端口
    pub dport: u32, // 目的端口
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockHashKey {}
