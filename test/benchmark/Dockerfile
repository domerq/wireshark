# Linux build environment for the memory-spill measurements.
#
# The spill code has platform-specific paths (hole punching, page release,
# writeback behaviour), and on Linux a cgroup memory limit replaces the
# malloc interposer needed on macOS, so the out-of-memory demonstration uses
# a real limit rather than a shim.
#
#   docker build -t wireshark-bench test/benchmark
#   docker run --rm -v "$PWD:/src:ro" -v wsbuild:/build \
#       -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory \
#       -e GIT_CONFIG_VALUE_0=/src wireshark-bench \
#       cmake -G Ninja -S /src -B /build -DBUILD_wireshark=OFF \
#           -DBUILD_sharkd=OFF -DENABLE_LUA=OFF
#       ninja -C /build tshark wmem_test reassemble_test
#
# Then, to show the failure a memory limit causes and that spilling survives
# it (adjust the limit to the capture; see README.md):
#
#   docker run --rm --memory=1g -v wsbuild:/build -v /tmp:/caps \
#       wireshark-bench /build/run/tshark -r /caps/big.pcap -q -z conv,tcp
#   docker run --rm --memory=1g -v wsbuild:/build -v /tmp:/caps \
#       wireshark-bench /build/run/tshark -r /caps/big.pcap --spill-dir /caps \
#           -q -z conv,tcp
#
# SPDX-License-Identifier: GPL-2.0-or-later

FROM ubuntu:24.04

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        flex \
        bison \
        python3 \
        git \
        time \
        libglib2.0-dev \
        libpcap-dev \
        libgcrypt20-dev \
        libc-ares-dev \
        libspeexdsp-dev \
        libxml2-dev \
        zlib1g-dev \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
