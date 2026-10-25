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
            -q -z conv,tcp
    # completes; resident set stays under the limit

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

    tshark -r big.pcap --spill-dir /tmp -q -z conv,tcp > spill.out
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
