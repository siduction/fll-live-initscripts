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
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <libudev.h>
#ifdef USE_LIBPIPELINE
#include <pipeline.h>
#endif

#include "fll_blockdev_cmdline.h"

struct gengetopt_args_info opts;
volatile sig_atomic_t timeout = 0;

static void handle_timeout(int signum)
{
	timeout = 1;
}

static void setup_timeout_signal(unsigned int seconds)
{
	struct sigaction sa;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = handle_timeout;
	sigaction(SIGALRM, &sa, NULL);

	alarm(seconds);
}

static int device_removable(struct udev_device *device)
{
	struct udev_device *parent = device;
	const char *removable;

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

static int print_device(struct udev_device *device)
{
	struct udev_list_entry *list_entry;
	struct udev_list_entry *first_list_entry;

	printf("--- %p ---\n", device);
	first_list_entry = udev_device_get_properties_list_entry(device);
	udev_list_entry_foreach(list_entry, first_list_entry) {
		printf("%s=\"%s\"\n",
		       udev_list_entry_get_name(list_entry),
		       udev_list_entry_get_value(list_entry));
	}

	return 0;
}

#ifdef USE_LIBPIPELINE
static int execp_device(struct udev_device *device)
{
	struct udev_list_entry *list_entry;
	struct udev_list_entry *first_list_entry;
	pipeline *pipe;
	pipecmd *cmd;
	int ret;

	pipe = pipeline_new();
	cmd = pipecmd_new(opts.execp_arg);

	first_list_entry = udev_device_get_properties_list_entry(device);
	udev_list_entry_foreach(list_entry, first_list_entry) {
		pipecmd_setenv(cmd, udev_list_entry_get_name(list_entry),
			       udev_list_entry_get_value(list_entry));
	}

	pipeline_command(pipe, cmd);
	ret = pipeline_run(pipe);

	return !ret;
}
#else
static int execp_device(struct udev_device *device)
{
	struct udev_list_entry *list_entry;
	struct udev_list_entry *first_list_entry;
	int ret;

	first_list_entry = udev_device_get_properties_list_entry(device);
	udev_list_entry_foreach(list_entry, first_list_entry) {
		setenv(udev_list_entry_get_name(list_entry),
		       udev_list_entry_get_value(list_entry), 1);
	}

	ret = system(opts.execp_arg);

	udev_list_entry_foreach(list_entry, first_list_entry) {
		unsetenv(udev_list_entry_get_name(list_entry));
	}

	return !ret;
}
#endif

static int process_device(struct udev_device *device)
{
	if (opts.execp_given)
		return execp_device(device);
	else
		return print_device(device);
}

int main(int argc, char **argv)
{
        struct udev *udev;
	struct udev_monitor *udev_monitor;
	struct udev_enumerate *u_enum;
        struct udev_list_entry *u_list_ent;
        struct udev_list_entry *u_first_list_ent;
	fd_set readfds;
	int fd;
	int ret = 0;

	if (cmdline_parser(argc, argv, &opts) != 0)
		return 1;

	udev = udev_new();
	if (udev == NULL) {
		fprintf(stderr, "Error: udev_new()\n");
		cmdline_parser_free(&opts);
		return 1;
	}

	/* enumerate existing block devices */
	u_enum = udev_enumerate_new(udev);
	if (u_enum == NULL) {
		fprintf(stderr, "Error: udev_enumerate_new(udev)\n");
		cmdline_parser_free(&opts);
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

		if (opts.removable_flag && !device_removable(device)) {
			udev_device_unref(device);
			continue;
		}

		ret = process_device(device);
		udev_device_unref(device);
		if (ret)
			break;
	}
	udev_enumerate_unref(u_enum);

	if (ret || !opts.monitor_flag) {
		cmdline_parser_free(&opts);
		udev_unref(udev);
		return !ret;
	}

	/* set an alarm to interupt the monitor loop */
	setup_timeout_signal(opts.timeout_arg);

	/* monitor add|change of block devices until timeout period expires */
	udev_monitor = udev_monitor_new_from_netlink(udev, "udev");
	if (udev_monitor == NULL) {
		fprintf(stderr, "Error: udev_monitor_new_from_netlink()\n");
		cmdline_parser_free(&opts);
		udev_unref(udev);
		return 1;
	}
	if (udev_monitor_filter_add_match_subsystem_devtype(udev_monitor,
							    "block",
							    "disk") < 0 ||
	    udev_monitor_filter_add_match_subsystem_devtype(udev_monitor,
							    "block",
							    "partition") < 0) {
		fprintf(stderr, "Error: udev_monitor_filter_add_match_subsystem_devtype()\n");
		cmdline_parser_free(&opts);
		udev_unref(udev);
		return 1;
	}
	if (udev_monitor_enable_receiving(udev_monitor) < 0) {
		fprintf(stderr, "Error: udev_monitor_enable_receiving()\n");
		cmdline_parser_free(&opts);
		udev_unref(udev);
		return 1;
	}

	fd = udev_monitor_get_fd(udev_monitor);

	while (!timeout) {
		struct udev_device *device;
		const char *action;

		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		if (select(fd + 1, &readfds, NULL, NULL, NULL) == -1) {
			if (errno != EINTR)
				fprintf(stderr, "Error: select(): %s\n",
					strerror(errno));
			break;
		}

		if (FD_ISSET(fd, &readfds)) {
			device = udev_monitor_receive_device(udev_monitor);
			if (device == NULL)
				continue;

			action = udev_device_get_action(device);
			if (strcmp(action, "add") != 0 &&
			    strcmp(action, "change") != 0) {
			    	udev_device_unref(device);
				continue;
			}

			if (opts.removable_flag && !device_removable(device)) {
				udev_device_unref(device);
				continue;
			}

			ret = process_device(device);
			udev_device_unref(device);
			if (ret)
				break;
		}
	}
	udev_monitor_unref(udev_monitor);

	cmdline_parser_free(&opts);
	udev_unref(udev);

	return !ret;
}
