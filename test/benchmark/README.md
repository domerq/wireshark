# Memory benchmarks

Tools for measuring how dissection state scales, and for reproducing the
numbers in `doc/README.memory-spill`. Nothing here runs as part of the test
suite; the captures are large and the runs take minutes.

## gen_pcap.py

Synthetic TCP captures with an exact packet and flow count, which is what
separates per-packet cost from per-flow cost:

    ./gen_pcap.py -c 1000000 -f 500   /tmp/few_flows.pcap
    ./gen_pcap.py -c 1000000 -f 500000 /tmp/many_flows.pcap

Same packet count, 1000x the flows. The difference in peak memory divided by
the difference in flow count is the per-conversation cost (~4 KB for TCP).

`-s N` writes N capture files instead of one, partitioned so that each holds
whole flows. That is the input a flow-sharded parallel dissection would give
each worker.

## flow_split.py

The same partitioning for a capture you already have, which is how the
four-worker numbers in `doc/README.memory-spill` section 7 were produced:

    ./flow_split.py big.pcap /tmp/shard -n 4
    # 9530000 packets, 412390 address pairs
    #   shard 0:    2382893 packets (1.00x ideal)
    #   ...

The key is the unordered IP address pair rather than the 5-tuple, so that IP
fragments stay with the flow they belong to, and pairs are assigned
longest-processing-time-first from a counting pass. Hashing the key instead
left the busiest shard 24% above ideal at 4 ways and 72% at 16; this stays
within 1% up to 16. Input must be pcap, not pcapng.

`tshark --shard-plan N` now computes the same division without writing
anything, and `tshark --jobs N` runs it; this script remains useful for
producing the separate files that measurements predating `--jobs` used,
and for feeding tools other than TShark.

## Dockerfile

The Linux side. Builds a tshark with the same options used for the
measurements and gives a real cgroup memory limit, which is a cleaner
out-of-memory demonstration than the interposer below (no shim, and the
kernel reclaims file-backed pages instead of killing the process):

    docker build -t wireshark-bench test/benchmark
    docker volume create wsbuild
    docker run --rm -v "$PWD:/src:ro" -v wsbuild:/build \
        -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory \
        -e GIT_CONFIG_VALUE_0=/src wireshark-bench \
        cmake -G Ninja -S /src -B /build -DCMAKE_BUILD_TYPE=RelWithDebInfo \
            -DBUILD_wireshark=OFF -DBUILD_stratoshark=OFF -DBUILD_sharkd=OFF \
            -DENABLE_LUA=OFF
    docker run --rm -v "$PWD:/src:ro" -v wsbuild:/build \
        -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory \
        -e GIT_CONFIG_VALUE_0=/src wireshark-bench \
        ninja -C /build tshark mergecap capinfos wmem_test reassemble_test

With a capture in a `wswork` volume, a 1 GB limit kills the unmodified run
and leaves the spilled one standing:

    docker run --rm --memory=1g -v wsbuild:/build -v wswork:/work \
        wireshark-bench /build/run/tshark -r /work/all.pcap -q -z conv,tcp
    # Killed (exit 137), no output

    docker run --rm --memory=1g -v wsbuild:/build -v wswork:/work \
        wireshark-bench /build/run/tshark -r /work/all.pcap --spill-dir /work \
            --spill-after 0 -q -z conv,tcp
    # completes; resident set stays under the limit

The watermark matters here: `--spill-after` defaults to 2048 MB, so without
it the store serves the first 2 GB from the heap and the run dies the same
way the unmodified one does. Set it below whatever limit is being imposed,
or to 0 to take the heap out of the picture entirely.

Keep the spill directory on a volume rather than the container's writable
layer, so that writeback is measured against a real filesystem.

## memcap

A `malloc` interposer that fails allocations past a budget, so an
out-of-memory condition is deterministic and does not depend on exhausting
the machine. It counts only malloc-family allocations, not file-backed
mappings, which is exactly the distinction `--spill-dir` is about.

It uses dyld interposition, so it is macOS only:

    cc -dynamiclib -O2 -o memcap.dylib memcap.c

(The Linux equivalent is an `LD_PRELOAD` shim that resolves the real
allocator with `dlsym(RTLD_NEXT, ...)`; it is not included here. A cgroup
memory limit achieves the same thing without any shim.)

Run with no budget to report peak heap:

    DYLD_INSERT_LIBRARIES=./memcap.dylib \
        tshark -r big.pcap -q -z conv,tcp >/dev/null
    # memcap: peak heap 9080 MB, live at exit 0 MB

Run with a budget to force the failure:

    export DYLD_INSERT_LIBRARIES=./memcap.dylib
    export MEMCAP_BYTES=$((512 * 1024 * 1024))

    tshark -r big.pcap -q -z conv,tcp > heap.out
    # GLib ERROR: failed to allocate 8388608 bytes - Aborting

    tshark -r big.pcap --spill-dir /tmp --spill-after 0 -q -z conv,tcp > spill.out
    # memcap: peak heap 141 MB
    cmp heap-unconstrained.out spill.out

Note that the interposer is stripped from the environment for setuid or
system binaries, so run the built `tshark` directly rather than through
`/usr/bin/time`.

## Measuring a real capture

`/usr/bin/time -l` (macOS) or `/usr/bin/time -v` (Linux) gives resident set
size, but for file-backed memory that is misleading: resident pages of the
spill file count towards RSS even though they are evictable without swap. Use
the interposer's peak heap for the number that matters, and TShark's own
"spilled dissection state" line at exit for how much went to disk.
