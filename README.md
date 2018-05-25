# fuse-wrapper
Simple wrapper to wrap files in a fuse container

1. Replace the payload variable with the hex encoded contents of your file.
2. Replace the payload_len variable with the file size in bytes
3. Compile to match target os
4. Execute the binary on the target, passing a directory to mount to

The file will have it's mode set to 4555, but fuse prevents actual exploitation.
You will have to find a backup, cp -a, or rsync type of function that passes over the mount point.i
Then reverse the process, or restore while unmounted to get a working 4555 file.

The defailt payload is just a binary file showing that there isn't any bad bytes.

```
gcc -Wall `pkg-config fuse --cflags --libs` fusefs.c -o fusefs
```
