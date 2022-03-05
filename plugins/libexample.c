/* libexample.c: Example code for writing a masterserver plugin. */
/* Copyright (C) 2003  Andre' Schulz
 * This file is part of masterserver.
 *
 * masterserver is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * masterserver is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with masterserver; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * The author can be contacted at chickenman@exhale.de
 */
/*
 * vim:sw=4:ts=4
 */

#include "../masterserver.h"

// for future use
// #define EXAMPLE_PROTOCOL IPPROTO_UDP
#define HEARTBEAT_TIMEOUT 300 // value represents seconds

#undef LOG_SUBNAME
#define LOG_SUBNAME "libexample" // logging category description

const char example_plugin_version[] = "0.3";
port_t example_ports[] = {	{ IPPROTO_UDP, 12345 },
							{ IPPROTO_UDP, 12346 },
							{ IPPROTO_UDP, 12347 } };

static void	info(void);
static int	process(char *); // process packet and return a value
static void	free_privdata(void *); // free private data
static void	cleanup(void); // clean up function in case of shutdown
void		init_plugin(void) __attribute__ ((constructor));

static
struct masterserver_plugin example
= { "example",
	example_plugin_vesrion,
	masterserver_version,
	example_ports,
	3,
	HEARTBEAT_TIMEOUT,
	&info,
	&process,
	&free_privdata,
	&cleanup
};

static void
info(void)
{
	INFO("example masterserver plugin v%s\n", example_plugin_version);
	INFO("  compiled for masterserver v%s\n", masterserver_version);
}

static int
process(char *packet)
{
	// insert packet processing code here
	return 0;
}

static void
free_privdata(void *privdata)
{
	// insert code here
}

static void
cleanup(void)
{
	// insert clean up code here
}

void
init_plugin(void)
{
	register_plugin(&example);
}

