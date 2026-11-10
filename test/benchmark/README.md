# Memory benchmarks

Tools for measuring how dissection state scales, and for reproducing the
numbers in `doc/README.memory-spill`. Nothing here runs as part of the test
suite; the captures are large and the runs take minutes.

## Quick check

The measurements below need multi-gigabyte captures and take minutes. This
section does not: a synthetic capture with enough flows to exceed a small
memory limit runs in about two seconds, which is enough to show that a run
dies without spilling, survives with it, and produces the same bytes either
way.

    test/benchmark/gen_pcap.py -c 300000 -f 150000 /tmp/quick.pcap
    # 26 MB on disk, ~700 MB of dissection state under -z conv,tcp
    # (everything below runs from the source root)

### macOS: a malloc budget

The interposer makes the limit deterministic, and counts only heap, which is
the whole point of the option. Build it once:

    cc -dynamiclib -O2 -o /tmp/memcap.dylib test/benchmark/memcap.c
    export DYLD_INSERT_LIBRARIES=/tmp/memcap.dylib

With no budget it reports what the run needs, and gives the reference output:

    build/run/tshark -r /tmp/quick.pcap -q -z conv,tcp > /tmp/ref.out
    # memcap: peak heap 796 MB, live at exit 0 MB

Then impose less than that:

    export MEMCAP_BYTES=$((512 * 1024 * 1024))

    build/run/tshark -r /tmp/quick.pcap -q -z conv,tcp
    # GLib ERROR failed to allocate 8388608 bytes - Aborting (0.4 s, no output)

    build/run/tshark -r /tmp/quick.pcap --spill-dir /tmp/spill -q -z conv,tcp
    # same abort: the default 2048 MB watermark is above the 512 MB budget

    build/run/tshark -r /tmp/quick.pcap --spill-dir /tmp/spill \
        --spill-after 256 -q -z conv,tcp > /tmp/spilled.out
    # dissection state: 256 MB peak in RAM, 448 MB peak spilled
    # memcap: peak heap 348 MB, live at exit 0 MB (1.5 s)
    cmp /tmp/ref.out /tmp/spilled.out

The middle run is the trap described in `doc/README.memory-spill` section 9:
the watermark has to be set below whatever limit is being imposed.

### Linux: a cgroup limit

A real limit, no shim. The container below is the one the Dockerfile builds
(see further down for the build; it is a one-off), and `wswork` is a volume
holding the capture, so the spill file is written to a real filesystem:

    docker volume create wswork
    docker run --rm -v "$PWD/caps:/caps:ro" -v wswork:/work \
        wireshark-bench cp /caps/quick.pcap /work/

    R="docker run --rm -v wsbuild:/build -v wswork:/work"

    $R wireshark-bench /build/run/tshark -r /work/quick.pcap \
        -q -z conv,tcp > /work/ref.out
    # 1.55 s, maximum resident set size 919 MB

    $R --memory=512m wireshark-bench /build/run/tshark -r /work/quick.pcap \
        -q -z conv,tcp
    # Killed (exit 137), nothing produced

    $R --memory=512m wireshark-bench /build/run/tshark -r /work/quick.pcap \
        --spill-dir /work -q -z conv,tcp
    # Killed the same way: the default 2048 MB watermark is above the limit

    $R --memory=512m wireshark-bench sh -c '/build/run/tshark \
        -r /work/quick.pcap --spill-dir /work --spill-after 256 \
        -q -z conv,tcp > /work/spilled.out; cmp /work/ref.out /work/spilled.out'
    # dissection state: 256 MB peak in RAM, 448 MB peak spilled (4.4 s)

Outside Docker the same limit is one command:

    systemd-run --user --scope -p MemoryMax=512M \
        build/run/tshark -r /tmp/quick.pcap --spill-dir /tmp/spill \
            --spill-after 256 -q -z conv,tcp

`ulimit -v` is the wrong tool for this and will not measure what it looks
like it measures: it caps address space, and the store deliberately maps far
more of that than it uses, so the run dies in the mapping rather than at the
limit being demonstrated:

    ulimit -v 524288
    build/run/tshark -r /work/quick.pcap --spill-dir /work --spill-after 256 ...
    # wmem_backing_base(): wmem: can't map 68719476736 bytes of the backing
    # file: Cannot allocate memory

Lowering `--spill-reserve` does not rescue it either, because the limit
applies to the mapping whatever its size. Use a cgroup.

### The GUI

Wireshark takes the same three options. Without a display, the offscreen
platform plugin loads a capture and can be measured the same way; the GUI has
no equivalent of TShark's report at exit, so the figure comes from vmmap:

    QT_QPA_PLATFORM=offscreen \
        build/run/Wireshark.app/Contents/MacOS/Wireshark -r /tmp/quick.pcap &
    vmmap -summary $! | grep -E 'Physical footprint|mapped file|^TOTAL'
    # Physical footprint 854.7M, of which 822.6M dirty malloc

    QT_QPA_PLATFORM=offscreen \
        build/run/Wireshark.app/Contents/MacOS/Wireshark -r /tmp/quick.pcap \
            --spill-dir /tmp/spill --spill-after 0 &
    vmmap -summary $! | grep -E 'Physical footprint|mapped file|^TOTAL'
    # Physical footprint 158.0M, 120.4M dirty malloc, 712.7M resident file pages

The state did not disappear - it moved to pages the kernel can evict without
swap, which is why footprint falls by 697 MB while the mapped file grows by
about as much. The equivalent reading on Linux is RssAnon against RssFile in
/proc/<pid>/status; the numbers above are macOS.

### Sharding, in the same two seconds

    build/run/tshark -r /tmp/quick.pcap --shard-plan 4
    # 300000 packets, 150000 address pairs, 0 with no IP pair
    #   shard 0:     75000 packets (1.00x ideal)   ... x4

    build/run/tshark -r /tmp/quick.pcap > /tmp/s1.out              # 1.3 s
    build/run/tshark -r /tmp/quick.pcap --jobs 4 > /tmp/s4.out     # 0.6 s
    cmp /tmp/s1.out /tmp/s4.out

The option combination is covered by the test suite, which needs no capture
of its own:

    pytest test/suite_clopts.py -k 'shard or jobs or spill' \
        --program-path build/run

## gen_pcap.py

Synthetic TCP captures with an exact packet and flow count, which is what
separates per-packet cost from per-flow cost, and what the two synthetic
rows in `doc/README.memory-spill` section 7 come from:

    ./gen_pcap.py -c 2000000 -f 50000  /tmp/few.pcap
    ./gen_pcap.py -c 1000000 -f 500000 /tmp/many.pcap

The difference in peak memory divided by the difference in flow count is the
per-conversation cost (~4 KB for TCP).

`-s N` writes N capture files instead of one, partitioned so that each holds
whole flows. That is the input a flow-sharded parallel dissection would give
each worker.

## flow_split.py

The same partitioning for a capture you already have, which is how the
four-worker numbers in `doc/README.memory-spill` section 7 were produced
before `--jobs` existed:

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

Run with no budget to report peak heap. The real capture used in
`doc/README.memory-spill` sections 7 and 9 is five days of the 2015-03
traffic merged into one file (1589 MB, 2033 k packets):

    build/run/mergecap -w /tmp/big.pcap 2015-03-0[5-9]/*

    DYLD_INSERT_LIBRARIES=/tmp/memcap.dylib \
        build/run/tshark -r /tmp/big.pcap -q -z conv,tcp > /tmp/ref.out
    # memcap: peak heap 2773 MB, live at exit 0 MB

The watermark table is the same run with a spill directory:

    DYLD_INSERT_LIBRARIES=/tmp/memcap.dylib \
        build/run/tshark -r /tmp/big.pcap --spill-dir /tmp/spill \
            --spill-after 1024 -q -z conv,tcp > /tmp/wm1024.out
    # dissection state: 1016 MB peak in RAM, 1687 MB peak spilled
    # memcap: peak heap 1083 MB, live at exit 0 MB
    cmp /tmp/ref.out /tmp/wm1024.out

Run with a budget below the state size to force the failure:

    export DYLD_INSERT_LIBRARIES=/tmp/memcap.dylib
    export MEMCAP_BYTES=$((1024 * 1024 * 1024))

    build/run/tshark -r /tmp/big.pcap -q -z conv,tcp > /tmp/oom1.out
    # GLib ERROR: failed to allocate 8388608 bytes - Aborting (2.8 s, no output)

    build/run/tshark -r /tmp/big.pcap --spill-dir /tmp/spill \
        -q -z conv,tcp > /tmp/oom2.out
    # same abort: the default 2048 MB watermark is above the 1024 MB budget

    build/run/tshark -r /tmp/big.pcap --spill-dir /tmp/spill \
        --spill-after 512 -q -z conv,tcp > /tmp/oom3.out
    # dissection state: 507 MB peak in RAM, 2196 MB peak spilled
    # memcap: peak heap 575 MB, live at exit 0 MB
    cmp /tmp/ref.out /tmp/oom3.out

Note that the interposer is stripped from the environment for setuid or
system binaries, so run the built `tshark` directly and time it with the
shell's `time` rather than through `/usr/bin/time`, which loses it.

## Measuring a real capture

`/usr/bin/time -l` (macOS) or `/usr/bin/time -v` (Linux) gives resident set
size, but for file-backed memory that is misleading: resident pages of the
spill file count towards RSS even though they are evictable without swap. Use
the interposer's peak heap for the number that matters, and TShark's own
"spilled dissection state" line at exit for how much went to disk.
