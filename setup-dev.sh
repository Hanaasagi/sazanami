#!/bin/bash
docker run -d --restart=always \
    -p 10080:1080 -p 10080:1080/udp --name socks5-server netbyte/socks5-server -l :1080
