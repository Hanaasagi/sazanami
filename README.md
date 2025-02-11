<h1 align="center"> Sazanami 🌊 Network </h1>

[![CI](https://github.com/Hanaasagi/sazanami/actions/workflows/ci.yaml/badge.svg)](https://github.com/Hanaasagi/sazanami/actions/workflows/ci.yaml)
[![codecov](https://codecov.io/gh/Hanaasagi/sazanami/branch/master/graph/badge.svg?token=5HYU2QTKZW)](https://codecov.io/gh/Hanaasagi/sazanami)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/fe79332f3c95478c9ff8190a0893d262)](https://app.codacy.com/gh/Hanaasagi/sazanami/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

**WARNING: This project has not been maintained since November 2023.**

Universal Proxy Client.

## Working mode

### 1) Tun Mode / design

![](https://user-images.githubusercontent.com/9482395/230949198-cc93c456-eced-404c-802d-373e7e7335d1.png)

### 2) eBPF Mode / design

WIP, Maybe use tc hook and smoltcp to take over the traffic.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain with the rust-src component: `rustup toolchain install nightly --component rust-src`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Configuration

```YAML
port: 1080
tun:
  name: "sazanami-tun"
  ip: 10.0.0.1
  cidr: 10.0.0.0/16
dns:
  upstream:
    - 8.8.8.8:53
    - 1.1.1.1:53
  timeout: 2s
  listen_at: "127.0.0.1:53"
connect_timeout: 2s
connect_retries: 2
read_timeout: 10s
write_timeout: 2000ms
proxies:
  - name: "Tokyo Sakura IPLC 01"
    type: ss
    server: 127.0.0.1
    port: 11451
    method: aes-128-gcm
    password: All-hail-chatgpt
    udp: true
# From https://github.com/Loyalsoldier/clash-rules
rules:
  - DOMAIN,clash.razord.top,DIRECT
  - DOMAIN,yacd.haishan.me,DIRECT
  - DOMAIN-SUFFIX,archlinux.org,DIRECT
  - DOMAIN-SUFFIX,office365.com,DIRECT
  - MATCH,PROXY
```

## Run

```bash
RUST_LOG=none,sazanami=info cargo xtask run -- --config example.yaml
```

<!-- ![out-5](https://user-images.githubusercontent.com/9482395/231234649-af857d62-5f99-4f01-8c25-cc0af3f4b9ac.png) [![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FHanaasagi%2Fsazanami.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FHanaasagi%2Fsazanami?ref=badge_shield)
!-->

## License

sazanami itself is GNU General Public License v3.0. And Some code referenced from the following projects in the project.

- [EAimTY/tuic](https://github.com/EAimTY/tuic) GNU General Public License v3.0
- [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust) MIT License
- [shoes](https://github.com/cfal/shoes) MIT License
- [v2ray-rust](https://github.com/Qv2ray/v2ray-rust) GNU Affero General Public License v3.0
- [aya-rs](https://github.com/aya-rs/aya) MIT License / Apache-2.0 License

Licenses cound be found in licenses directory.

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FHanaasagi%2Fsazanami.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FHanaasagi%2Fsazanami?ref=badge_large)
