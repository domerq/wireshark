#!/usr/bin/env python3
#
# Generate synthetic TCP captures with a chosen number of packets and flows,
# for measuring how dissection state scales with each (see
# doc/README.memory-spill).
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Generate a synthetic TCP capture with a given packet and flow count.'''

import argparse
import struct

PCAP_HEADER = struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
ETHERNET = bytes.fromhex('001122334455') + bytes.fromhex('66778899aabb') + b'\x08\x00'
PAYLOAD = b'\xab' * 20


def flow_packet(flow, index):
    '''One TCP segment belonging to the given flow.'''
    src = 0x0a000000 | (flow & 0xffff)
    dst = 0xc0a80000 | ((flow >> 16) & 0xffff)
    ip = struct.pack('!BBHHHBBH', 0x45, 0, 40 + len(PAYLOAD), flow & 0xffff,
                     0x4000, 64, 6, 0) + struct.pack('!II', src, dst)
    tcp = struct.pack('!HHIIBBHHH', 1024 + (flow % 40000), 80,
                      index * len(PAYLOAD) + 1, 1, 0x50, 0x10, 65535, 0, 0)
    return ETHERNET + ip + tcp + PAYLOAD


def write_capture(path, packets, flows, shards):
    '''Write packets round-robin over flows, optionally split by flow.

    With shards > 1 the flows are partitioned between <path>0 .. <path>N-1,
    so that each file holds whole flows. That is what a flow-sharded parallel
    dissection would feed each worker.
    '''
    if shards == 1:
        files = [open(path, 'wb')]
    else:
        base = path[:-5] if path.endswith('.pcap') else path
        files = [open('%s%d.pcap' % (base, i), 'wb') for i in range(shards)]

    for out in files:
        out.write(PCAP_HEADER)

    for i in range(packets):
        flow = i % flows
        packet = flow_packet(flow, i // flows)
        out = files[flow % shards]
        out.write(struct.pack('<IIII', 1700000000 + i // 10000,
                              (i % 10000) * 100, len(packet), len(packet)))
        out.write(packet)

    for out in files:
        out.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', help='output capture file')
    parser.add_argument('-c', '--packets', type=int, default=1000000)
    parser.add_argument('-f', '--flows', type=int, default=50000)
    parser.add_argument('-s', '--shards', type=int, default=1,
                        help='split the flows over this many capture files')
    args = parser.parse_args()

    write_capture(args.path, args.packets, args.flows, args.shards)


if __name__ == '__main__':
    main()
