#![no_std]
#![no_main]

use core::mem;

use aya_bpf::bindings::sk_action;
use aya_bpf::bindings::BPF_F_INGRESS;
use aya_bpf::bindings::BPF_NOEXIST;
use aya_bpf::bindings::BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB;
use aya_bpf::bindings::BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB;
use aya_bpf::macros::map;
use aya_bpf::macros::sk_msg;
use aya_bpf::macros::sock_ops;
use aya_bpf::macros::socket_filter;
use aya_bpf::maps::SockHash;
use aya_bpf::programs::SkBuffContext;
use aya_bpf::programs::SkMsgContext;
use aya_bpf::programs::SockOpsContext;
use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::IpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use sazanami_common::SockHashKey;

pub const CAPACITY: usize = 8192;

#[map]
static mut SOCKHASH: SockHash<SockHashKey> = SockHash::with_max_entries(CAPACITY as u32, 0);

fn bpf_sock_ops_ipv4(ctx: SockOpsContext) {
    let mut key = SockHashKey {
        sip4: ctx.local_ip4(),
        dip4: ctx.remote_ip4(),
        family: 1,
        pad1: 0,
        pad2: 0,
        pad3: 0,
        sport: unsafe { u32::from_be((*ctx.ops).local_port) },
        dport: ctx.remote_port(),
    };

    let ops = unsafe { ctx.ops.as_mut().unwrap() };
    let ret = unsafe { SOCKHASH.update(&mut key, ops, BPF_NOEXIST.into()) };

    ret.expect("SockHash error");
}

#[sock_ops]
pub fn bpf_sockmap(ctx: SockOpsContext) -> u32 {
    if ctx.op() == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB {
        if ctx.family() == 2 {
            // info!(
            //     &ctx,
            //     "BPF sock map passive established sport {} dport {}",
            //     ctx.local_port(),
            //     unsafe { u32::from_be((*ctx.ops).remote_port) }
            // );
            bpf_sock_ops_ipv4(ctx);
        }
        return 0;
    }
    if ctx.op() == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB {
        if ctx.family() == 2 {
            // info!(
            //     &ctx,
            //     "BPF sock map active established sport {} dport {}",
            //     ctx.local_port(),
            //     unsafe { u32::from_be((*ctx.ops).remote_port) }
            // );
            bpf_sock_ops_ipv4(ctx);
        }
        return 0;
    }
    return 0;
}

#[sk_msg]
pub fn bpf_redir(ctx: SkMsgContext) -> u32 {
    let mut key = unsafe {
        SockHashKey {
            sip4: (*ctx.msg).remote_ip4,
            dip4: (*ctx.msg).local_ip4,
            family: 1,
            pad1: 0,
            pad2: 0,
            pad3: 0,
            sport: (*ctx.msg).remote_port,
            dport: unsafe { u32::from_be((*ctx.msg).local_port) },
        }
    };

    // info!(
    //     &ctx,
    //     "redirect to local_ip4={:ipv4}:{} remote_ip4={:ipv4}:{}",
    //     key.dip4,
    //     key.dport,
    //     key.sip4,
    //     unsafe { u32::from_be((*ctx.msg).remote_port) },
    // );
    let ret = unsafe { SOCKHASH.redirect_msg(&ctx, &mut key, BPF_F_INGRESS as u64) };

    if ret == 1 {
        // info!(&ctx, "redirect_msg succeed");
    } else {
        // info!(&ctx, "redirect_msg failed");
    }

    return sk_action::SK_PASS;
}

const ETH_HDR_LEN: usize = mem::size_of::<EthHdr>();
const IP_HDR_LEN: usize = mem::size_of::<IpHdr>();
const TCP_HDR_LEN: usize = mem::size_of::<TcpHdr>();
#[repr(C)]
pub struct Buf {
    pub buf: [u8; 1500],
}
///
/// #[map]
/// pub static mut BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);
///
/// fn try_cgroup_skb(ctx: SkBuffContext) -> Result<i32, i32> {
///     let buf = unsafe {
///         let ptr = BUF.get_ptr_mut(0).ok_or(TC_ACT_PIPE)?;
///         &mut *ptr
///     };
///     let offset = ETH_HDR_LEN + IP_HDR_LEN + TCP_HDR_LEN;
///     ctx.load_bytes(offset, &mut buf.buf).map_err(|_| TC_ACT_PIPE)?;
///
///     // do something with `buf`
///
///     Ok(TC_ACT_PIPE)
/// }

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &SkBuffContext, offset: usize) -> Result<*const T, ()> {
    let start = unsafe { (*ctx.skb.skb).data as usize };
    let end = unsafe { (*ctx.skb.skb).data_end as usize };
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

// #[socket_filter]
// pub fn socket_filter(ctx: SkBuffContext) -> i64 {
//     if (ctx.skb.protocol() != 2) {
//         return 0;
//     }

//     ctx.skb.remote_ipv4();

//     return 0;
// }

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
