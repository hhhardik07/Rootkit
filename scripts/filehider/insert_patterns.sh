#!/bin/bash

# Insert pattern into the map (e.g., hide all .tmp files)
bpftool map update /sys/fs/bpf/file_hiding patterns key="*.tmp" value=1

# Insert another pattern (e.g., hide files starting with 'anything_') for anything the user wnats to put
bpftool map update /sys/fs/bpf/file_hiding patterns key="anything*" value=1

echo "✅ Patterns inserted into the map:"
bpftool map dump /sys/fs/bpf/file_hiding
