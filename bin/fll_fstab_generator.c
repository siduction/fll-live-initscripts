/*
 *  Copyright (C) 2010  Kel Modderman <kel@otaku42.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, see <http://www.gnu.org/licenses>
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <mntent.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <unistd.h>
#include <libudev.h>
#include <blkid/blkid.h>

#include "fll_fstab_cmdline.h"

struct gengetopt_args_info opts;
FILE *fstab;
int mounted;

static int linux_filesystem(const char *fstype)
{
	if (strcmp(fstype, "swap") == 0)
		return 1;
	if (strcmp(fstype, "ext4") == 0)
		return 1;
	if (strcmp(fstype, "ext3") == 0)
		return 1;
	if (strcmp(fstype, "ext2") == 0)
		return 1;
	if (strcmp(fstype, "xfs") == 0)
		return 1;
	if (strcmp(fstype, "jfs") == 0)
		return 1;
	if (strcmp(fstype, "reiserfs") == 0)
		return 1;
	if (strcmp(fstype, "reiser4") == 0)
		return 1;
	if (strcmp(fstype, "btrfs") == 0)
		return 1;
	
	return 0;
}

static int device_flagged(struct udev_device *device, unsigned int flagged,
			  char **a)
{
	struct udev_device *parent = device;
	struct udev_list_entry *u_list_ent;
	struct udev_list_entry *u_first_list_ent;
	const char *devnode;
	int i;

	if (!flagged)
		return 0;

	do {
		devnode = udev_device_get_devnode(parent);
		if (devnode == NULL)
			break;

		for (i = 0; i < flagged; ++i) {
			if (strcmp(devnode, a[i]) == 0)
				return 1;
			else if (strcmp(basename(devnode), a[i]) == 0)
				return 1;
		}

		u_first_list_ent = udev_device_get_devlinks_list_entry(parent);
		udev_list_entry_foreach(u_list_ent, u_first_list_ent) {
			devnode = udev_list_entry_get_name(u_list_ent);
			for (i = 0; i < flagged; ++i) {
				if (strcmp(devnode, a[i]) == 0)
					return 1;
				else if (strcmp(basename(devnode), a[i]) == 0)
					return 1;
			}
		}
		parent = udev_device_get_parent_with_subsystem_devtype(parent,
								       "block",
								       "disk");
	} while (parent != NULL);

	return 0;
}

static int device_removable(struct udev_device *device)
{
	struct udev_device *parent = device;
	const char *removable;

	if (opts.removable_flag)
		return 0;

	do {
		removable = udev_device_get_sysattr_value(parent,
							  "removable");
		if (removable != NULL)
			return atoi(removable);
		parent = udev_device_get_parent_with_subsystem_devtype(parent,
								       "block",
								       "disk");
	} while (parent != NULL);

	return 1;
}

static int device_devtype_disk(struct udev_device *device)
{
	const char *devtype;

	devtype =  udev_device_get_devtype(device);
	if (devtype != NULL)
		return strcmp(devtype, "disk") == 0;
	
	return 0;
}

static int device_devmapper(struct udev_device *device)
{
	const char *devnode;

	devnode = udev_device_get_devnode(device);
	if (devnode != NULL)
		return strncmp(devnode, "/dev/mapper/",
			       strlen("/dev/mapper/")) == 0;
	else
		return 0;
}

static char* device_vfstype(struct udev_device *device)
{
	const char *fstype;
	char *value;
	blkid_probe pr;
	uint64_t size;
	int fd;
	size_t len;
	int res;

	value = NULL;

	if (opts.blkid_flag) {
		fd = open(udev_device_get_devnode(device), O_RDONLY);
		if (fd < 0)
			return NULL;
		
		pr = blkid_new_probe();
		if (pr == NULL) {
			fprintf(stderr, "Error: blkid_new_probe()\n");
			close(fd);
			return NULL;
		}
		
		blkid_probe_set_request(pr, BLKID_PROBREQ_TYPE);
		
		if (ioctl(fd, BLKGETSIZE64, &size) != 0)
			size = 0;
		
		if (blkid_probe_set_device(pr, fd, 0, size) != 0 ||
		    blkid_do_safeprobe(pr) != 0 ||
		    blkid_probe_lookup_value(pr, "TYPE", &fstype, NULL) != 0) {
			blkid_free_probe(pr);
			close(fd);
			return NULL;
		}

		len = strlen(fstype) + 1;
		value = malloc(len);
		if (value == NULL) {
			blkid_free_probe(pr);
			close(fd);
			return NULL;
		}
		res = snprintf(value, len, "%s", fstype);
		if (res < 0 || (size_t) res >= len) {
			blkid_free_probe(pr);
			close(fd);
			return NULL;
		}
		else
			value[len - 1] = '\0';

		blkid_free_probe(pr);
		close(fd);
	}
	else {
		fstype = udev_device_get_property_value(device, "ID_FS_TYPE");
		if (fstype == NULL)
			return NULL;
		len = strlen(fstype) + 1;
		value = malloc(len);
		if (value == NULL)
			return NULL;
		res = snprintf(value, len, "%s", fstype);
		if (res < 0 || (size_t) res >= len)
			return NULL;
		else
			value[len - 1] = '\0';
	}

	return value;
}

static char* device_spec(struct udev_device *device, char *fstype, int disk)
{
	struct udev_list_entry *u_list_ent;
	struct udev_list_entry *u_first_list_ent;
	const char *devnode;
	char *value;
	size_t len;
	int res;

	value = NULL;
	u_first_list_ent = udev_device_get_devlinks_list_entry(device);

	if (disk && (opts.labels_flag || opts.uuids_flag)) {
		udev_list_entry_foreach(u_list_ent, u_first_list_ent) {
			devnode = udev_list_entry_get_name(u_list_ent);
			if (opts.labels_flag &&
			    strncmp(devnode, "/dev/disk/by-label",
			    	    strlen("/dev/disk/by-label")) == 0) {
				if (value != NULL)
					free(value);
				len = strlen("LABEL=") + 1;
				len += strlen(basename(devnode));
				value = malloc(len);
				if (value == NULL)
					return NULL;
				res = snprintf(value, len, "LABEL=%s",
					       basename(devnode));
				if (res < 0 || (size_t) res >= len)
					return NULL;
				else
					value[len - 1] = '\0';
			}
			if (opts.uuids_flag &&
			    strncmp(devnode, "/dev/disk/by-uuid",
				    strlen("/dev/disk/by-uuid")) == 0) {
				if (value != NULL)
					free(value);
				len = strlen("UUID=") + 1;
				len += strlen(basename(devnode));
				value = malloc(len);
				if (value == NULL)
					return NULL;
				res = snprintf(value, len, "UUID=%s",
					       basename(devnode));
				if (res < 0 || (size_t) res >= len)
					return NULL;
				else
					value[len - 1] = '\0';
			}
		}
	}

	if (!disk || value == NULL) {
		devnode = udev_device_get_devnode(device);
		if (devnode == NULL)
			return NULL;
		len = strlen(devnode) + 1;
		value = malloc(len);
		if (value == NULL)
			return NULL;
		res = snprintf(value, len, "%s", devnode);
		if (res < 0 || (size_t) res >= len)
			return NULL;
		else
			value[len - 1] = '\0';
	}

	return value;
}

static char* device_file(struct udev_device *device, int disk)
{
	struct udev_list_entry *u_list_ent;
	struct udev_list_entry *u_first_list_ent;
	FILE *fp;
	struct mntent *mnt;
	const char *devnode;
	const char *fstype;
	const char *partition;
	char *value;
	size_t len;
	int res;

	value = NULL;
	u_first_list_ent = udev_device_get_devlinks_list_entry(device);

	if (!opts.nomounts_flag) {
		fstype = udev_device_get_property_value(device, "ID_FS_TYPE");
		fp = setmntent("/proc/mounts", "r");

		for (;;) {
			if (fp == NULL || fstype == NULL)
				break;

			mnt = getmntent(fp);
			if (mnt == NULL)
				break;

			if (strcmp(fstype, mnt->mnt_type) != 0)
				continue;

			if (strcmp(udev_device_get_devnode(device),
				   mnt->mnt_fsname) == 0) {
				len = strlen(mnt->mnt_dir) + 1;
				value = malloc(len);
				if (value == NULL)
					return NULL;
				res = snprintf(value, len, "%s", mnt->mnt_dir);
				if (res < 0 || (size_t) res >= len)
					return NULL;
				else
					value[len - 1] = '\0';
				mounted = 1;
				break;
			}

			udev_list_entry_foreach(u_list_ent, u_first_list_ent) {
				devnode = udev_list_entry_get_name(u_list_ent);
				if (strcmp(devnode, mnt->mnt_fsname) != 0)
					continue;
				len = strlen(mnt->mnt_dir) + 1;
				value = malloc(len);
				if (value == NULL)
					return NULL;
				res = snprintf(value, len, "%s", mnt->mnt_dir);
				if (res < 0 || (size_t) res >= len)
					return NULL;
				else
					value[len - 1] = '\0';
				mounted = 1;
				break;
			}
		}
		if (fp != NULL)
			endmntent(fp);
	}

	if (value == NULL) {
		if (!disk) {
			devnode = udev_device_get_devnode(device);
			len = strlen("/disks/");
			len += strlen(basename(devnode)) + 1;
			value = malloc(len);
			if (value == NULL)
				return NULL;
			res = snprintf(value, len, "/disks/%s",
				       basename(devnode));
			if (res < 0 || (size_t) res >= len)
				return NULL;
			else
				value[len - 1] = '\0';
		}
		else {
			partition = udev_device_get_sysattr_value(device,
								  "partition");
			if (partition != NULL) {
				len = strlen("/disks/disk");
				if (disk < 10)
					len += 1;
				else if (disk < 100)
					len += 2;
				else
					len += 3;
				len += strlen("part") + strlen(partition) + 1;
				value = malloc(len);
				if (value == NULL)
					return NULL;
				res = snprintf(value, len,
					       "/disks/disk%dpart%s",
					       disk, partition);
				if (res < 0 || (size_t) res >= len)
					return NULL;
				else
					value[len - 1] = '\0';
			}
			else {
				len = strlen("/disks/disk");
				if (disk < 10)
					len += 1;
				else if (disk < 100)
					len += 2;
				else
					len += 3;
				len += 1;
				value = malloc(len);
				if (value == NULL)
					return NULL;
				res = snprintf(value, len, "/disks/disk%d",
					       disk);
				if (res < 0 || (size_t) res >= len)
					return NULL;
				else
					value[len - 1] = '\0';
			}
		}
	}

	return value;
}

static char* device_mntops(struct udev_device *device, char *fstype, char *dir)
{
	const char *str;
	char *value;
	size_t len;
	int res;

	value = NULL;

	if (mounted && linux_filesystem(fstype)) {
		if ((strcmp(fstype, "ext4") == 0) ||
		    (strcmp(fstype, "ext3") == 0) ||
		    (strcmp(fstype, "ext2") == 0))
			str = "defaults,relatime,errors=remount-ro";
		else
			str = "defaults,relatime";

		len = strlen(str) + 1;
		value = malloc(len);
		if (value == NULL)
			return NULL;
		res = snprintf(value, len, "%s", str);
		if (res < 0 || (size_t) res >= len)
			return NULL;
		else
			value[len - 1] = '\0';
		
	}
	else {
		if (linux_filesystem(fstype))
			str = "users,rw,exec,relatime";
		else if (strcmp(fstype, "ntfs") == 0)
			str = "users,ro,dmask=0022,fmask=0133,nls=utf8";
		else if (strcmp(fstype, "msdos") == 0)
			str = "users,rw,quiet,umask=000,iocharset=utf8";
		else if (strcmp(fstype, "vfat") == 0)
			str = "users,rw,quiet,umask=000";
		else if (strcmp(fstype, "hfsplus") == 0)
			str = "users,ro,exec";
		else
			return NULL;

		len = strlen(str) + 1;
		if (opts.auto_flag)
			len += strlen("auto") + 1;
		else
			len += strlen("noauto") + 1;
		value = malloc(len);
		if (value == NULL)
			return NULL;
		res = snprintf(value, len, "%s,%s",
			       opts.auto_flag ? "auto" : "noauto", str);
		if (res < 0 || (size_t) res >= len)
			return NULL;
		else
			value[len - 1] = '\0';
	}

	return value;
}

static void print_mntent(const char *fs_spec, const char *fs_file,
			 const char *fs_vfstype, const char *fs_mntops,
			 int fs_freq, int fs_passno)
{
	fprintf(fstab, "%s %s %s %s %d %d\n", fs_spec, fs_file, fs_vfstype,
		fs_mntops, fs_freq, fs_passno);
}

static void process_disk(struct udev_device *device, int disk)
{
	char *fs_spec = NULL;
	char *fs_file = NULL;
	char *fs_vfstype = NULL;
	char *fs_mntops = NULL;
	int fs_pass = 0;

	mounted = 0;

	fs_vfstype = device_vfstype(device);
	if (fs_vfstype == NULL)
		goto end_process_disk;
	
	fs_spec = device_spec(device, fs_vfstype, disk);
	if (fs_spec == NULL)
		goto end_process_disk;

	if (strcmp(fs_vfstype, "swap") == 0) {
		if (opts.noswap_flag)
			goto end_process_disk;

		print_mntent(fs_spec, "none", fs_vfstype, "sw", 0, 0);

		if (opts.swapon_flag &&
		    swapon(udev_device_get_devnode(device), 0) == -1) {
		    	if (errno != EBUSY)
				fprintf(stderr, "Error: swapon(%s): %s\n",
					udev_device_get_devnode(device),
					strerror(errno));
		}

		goto end_process_disk;
	}

	fs_file = device_file(device, disk);
	if (fs_file == NULL)
		goto end_process_disk;
	
	fs_mntops = device_mntops(device, fs_vfstype, fs_file);
	if (fs_mntops == NULL)
		goto end_process_disk;
	
	if (mounted) {
		if (strcmp(fs_file, "/") == 0)
			fs_pass = 1;
		else if (linux_filesystem(fs_vfstype))
			fs_pass = 2;
	}
	
	if (opts.mkdir_flag && 
	    mkdir(fs_file, S_IRWXU | S_IRWXG | S_IRWXO) == -1) {
		if (errno != EEXIST) {
			fprintf(stderr, "Error: mkdir(%s): %s\n", fs_file,
				strerror(errno));
			goto end_process_disk;
		}
	}

	print_mntent(fs_spec, fs_file, fs_vfstype, fs_mntops, 0, fs_pass);

end_process_disk:
	if (fs_spec != NULL)
		free(fs_spec);
	if (fs_vfstype != NULL)
		free(fs_vfstype);
	if (fs_file != NULL)
		free(fs_file);
	if (fs_mntops != NULL)
		free(fs_mntops);
}

int main(int argc, char **argv)
{
        struct udev *udev;
	struct udev_enumerate *u_enum;
        struct udev_list_entry *u_list_ent;
        struct udev_list_entry *u_first_list_ent;
	int disk = 0;

	if (cmdline_parser(argc, argv, &opts) != 0) {
		fprintf(stderr, "Error: cmdline_parser(argc, argv, &opts)\n");
		return 1;
	}

	if (opts.file_given) {
		fstab = fopen(opts.file_arg, "w");
		if (fstab == NULL) {
			fprintf(stderr, "Error: fpopen(%s): %s\n",
				opts.file_arg, strerror(errno));
			cmdline_parser_free(&opts);
			return 1;
		}
	}
	else
		fstab = stdout;

	udev = udev_new();
	if (udev == NULL) {
		fprintf(stderr, "Error: udev_new()\n");
		cmdline_parser_free(&opts);
		fclose(fstab);
		return 1;
	}

	u_enum = udev_enumerate_new(udev);
	if (u_enum == NULL) {
		fprintf(stderr, "Error: udev_enumerate_new(udev)\n");
		cmdline_parser_free(&opts);
		fclose(fstab);
		udev_unref(udev);
		return 1;
	}

	udev_enumerate_add_match_subsystem(u_enum, "block");
	udev_enumerate_add_match_property(u_enum, "DEVTYPE", "disk");
	udev_enumerate_add_match_property(u_enum, "DEVTYPE", "partition");
	udev_enumerate_scan_devices(u_enum);

	u_first_list_ent = udev_enumerate_get_list_entry(u_enum);
	udev_list_entry_foreach(u_list_ent, u_first_list_ent) {
		struct udev_device *device;
		struct udev *context;
		const char *name;

		context = udev_enumerate_get_udev(u_enum);
		name = udev_list_entry_get_name(u_list_ent);
		device = udev_device_new_from_syspath(context, name);
		if (device == NULL)
			continue;

		if (device_flagged(device, opts.ignore_given,
				   opts.ignore_arg)) {
			udev_device_unref(device);
			continue;
		}
		else if (opts.inputs_num) {
			if (device_removable(device) ||
			    !device_flagged(device, opts.inputs_num,
					    opts.inputs)) {
				udev_device_unref(device);
				continue;
			}
		}
		else if (device_removable(device)) {
			if (!device_flagged(device, opts.wanted_given,
					    opts.wanted_arg)) {
				udev_device_unref(device);
				continue;
			}
		}

		if (device_devtype_disk(device))
			disk++;

		if (device_devmapper(device))
			process_disk(device, 0);
		else
			process_disk(device, disk);

		udev_device_unref(device);
	}
	udev_enumerate_unref(u_enum);
	udev_unref(udev);
	fclose(fstab);
	cmdline_parser_free(&opts);
	return 0;
}
