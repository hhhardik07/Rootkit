Step 1:
 Compile and load the program
 ./load_attach.sh

Step 2:
 insert patterns 
 ./insert_patterns.sh

Step 3:
 check what's in the map
 bpftool map dump /sys/fs/bpf/file_hider
