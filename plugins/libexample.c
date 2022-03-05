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
 * The author can be contacted at andre@malchen.de
 */

#include "../masterserver.h"

// for future use
// #define EXAMPLE_PROTOCOL IPPROTO_UDP
#define EXAMPLE_PLUGIN_VERSION_MAJOR 0
#define EXAMPLE_PLUGIN_VERSION_MINOR 3
#define HEARTBEAT_TIMEOUT 300 // value represents seconds

#undef LOG_SUBNAME
#define LOG_SUBNAME "libexample" // logging category description

const char example_plugin_version[] = "0.3";
int example_ports[] = { 12345, 12346, 12347 };

static void info(void);
static int process(char *packet); // process packet and return a value


static
struct masterserver_plugin example
= { "example",
	example_plugin_vesrion,
	masterserver_version,
	example_ports,
	3,
	// EXAMPLE_PROTOCOL, // for future use
	HEARTBEAT_TIMEOUT,
	&info,
	&process,
	&cleanup
};

static void
info(void)
{
	INFO("example masterserver plugin v%s\n", example_plugin_version);
	INFO("  compiled for masterserver v%s\n", masterserver_version);
}

static unsigned int
process(char *packet)
{
	// insert packet processing code here
	return 0;
}

static void
cleanup(void)
{
	// insert clean up code here
}

void
_init(void)
{
	register_plugin(&example);
}

