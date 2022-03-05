/* libh2.c: masterserver plugin for Heretic2 servers. */
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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h> // for socket() etc.
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../masterserver.h"

#define HEARTBEAT_TIMEOUT 300

#undef LOG_SUBNAME
#define LOG_SUBNAME "libh2" // logging subcategory description

const char	h2_pkt_header[]		= "\xff\xff\xff\xff";
const int	h2_pkt_header_len	= 4;
// we just check for the keyword
const char	h2_pkt_heartbeat[]	= "heartbeat";
const int	h2_pkt_heartbeat_len= 9;
const char	h2_pkt_query[]		= "query";
const int	h2_pkt_query_len	= 5;
const char	h2_pkt_servers[]	= "servers ";
const int	h2_pkt_servers_len	= 8;
const char	h2_pkt_shutdown[]	= "shutdown";
const int	h2_pkt_shutdown_len	= 8;
const char	h2_pkt_ping[]		= "ping";
const int	h2_pkt_ping_len		= 4;
const char	h2_pkt_ack[]		= "ack";
const int	h2_pkt_ack_len		= 3;

const char h2m_plugin_version[] = "0.4";
static port_t h2m_ports[] = { { IPPROTO_UDP, 28900 } };

static void	info(void); // print information about plugin
static int	process(char *, int); // process packet and return a value
static int	process_heartbeat(char *);
static int	process_shutdown(char *);
static int	process_ping(char *);
static int	process_query(char *);
void		init_plugin(void) __attribute__ ((constructor));

static
struct masterserver_plugin h2m
= { "h2m",
	h2m_plugin_version,
	masterserver_version,
	h2m_ports,
	1,
	HEARTBEAT_TIMEOUT,
	&info,
	&process,
	NULL,	// free_privdata()
	NULL	// cleanup()
};

static void
info(void)
{
	INFO("heretic2 masterserver plugin v%s\n", h2m_plugin_version);
	INFO("  compiled for masterserver v%s\n", masterserver_version);
}

static int
process_heartbeat(char *packet)
{
	int i, server_dup = 0, time_diff; // temp vars

	// first, check if server is already in our list
	for (i = 0; i < h2m.num_servers; i++) {
		if ((h2m.list[i].ip.s_addr == h2m.client.sin_addr.s_addr)
				&& (h2m.list[i].port == h2m.client.sin_port)) {
			DEBUG("duplicate server detected! (%s:%d)\n",
				inet_ntoa(h2m.client.sin_addr), ntohs(h2m.client.sin_port));
			server_dup = 1;
			break;
		}
	}

	INFO("heartbeat from %s:%d\n",
			inet_ntoa(h2m.client.sin_addr), ntohs(h2m.client.sin_port));
	// if not, then add it to the list
	if (!server_dup) {
		h2m.list[h2m.num_servers].ip = h2m.client.sin_addr;
		h2m.list[h2m.num_servers].port = h2m.client.sin_port;
		h2m.list[h2m.num_servers].lastheartbeat = time(NULL);
		h2m.num_servers++;

		DEBUG("reallocating server list (old size: %d -> new size: %d)\n",
			h2m.num_servers * sizeof(serverlist_t),
			(h2m.num_servers+1) * sizeof(serverlist_t));

		h2m.list = realloc(h2m.list, ((h2m.num_servers + 1) * sizeof(serverlist_t)));
		if (h2m.list == NULL) {
			ERRORV("realloc() failed trying to get %d bytes!\n",
					(h2m.num_servers+1)*sizeof(serverlist_t));
			pthread_exit((void *) -1);
		} else DEBUG("reallocation successful\n");
	} else {
		time_diff = time(NULL) - h2m.list[i].lastheartbeat;
		// server is already in our list so we just update the timestamp
		h2m.list[i].lastheartbeat = time(NULL);
		server_dup = 0;
	}
	return 0; // server added to list
} // process_heartbeat()

static int
process_shutdown(char *packet)
{
	int i, time_diff, server_dup = 0;

	// sanity check num_servers
	for (i = 0; i < h2m.num_servers; i++) {
		if ((h2m.list[i].ip.s_addr == h2m.client.sin_addr.s_addr)
				&& (h2m.list[i].port == h2m.client.sin_port)) {
			server_dup = 1;
			break;
		}
	}

	if (server_dup) {
		time_diff = time(NULL) - h2m.list[i].lastheartbeat;
		INFO("server %s:%u is shutting down (time_diff %d)\n",
			inet_ntoa(h2m.list[i].ip), ntohs(h2m.list[i].port), time_diff);
		delete_server(&h2m, i);
		return 2; // return "server shutdown" code
	} else return -1; // invalid packet
} // process_shutdown()

static int
process_ping(char *packet)
{
	INFO("ping from %s:%d\n", inet_ntoa(h2m.client.sin_addr), ntohs(h2m.client.sin_port));
	// allocate memory for msg_out_length array
	h2m.msg_out_length = calloc(1, sizeof(int));
	if (h2m.msg_out_length == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(int));
		return -2;
	}

	// write length of packet
	h2m.msg_out_length[0] = h2_pkt_header_len + h2_pkt_ack_len;

	// allocate memory for packet pointers (we only send 1)
	h2m.msg_out = calloc(1, sizeof(char *));
	if (h2m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(char *));
		return -2;
	}

	// allocate memory for the packet itself
	h2m.msg_out[0] = calloc(h2m.msg_out_length[0]+1, 1);
	if (h2m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				h2m.msg_out_length[0]+1);
		return -2;
	}

	// write packet contents
	memcpy(h2m.msg_out[0], h2_pkt_header, h2_pkt_header_len);
	memcpy(h2m.msg_out[0]+h2_pkt_header_len, h2_pkt_ack, h2_pkt_ack_len);

	h2m.num_msgs = 1;

	return 1; // tell masterserver to send it out
} // process_ping()

static int
process_query(char *packet)
{
	int i; // temp var
	int msg_out_offset; // temp var for keeping track of where were writing the outgoing packet

	INFO("query from %s:%d\n",
		inet_ntoa(h2m.client.sin_addr), ntohs(h2m.client.sin_port));

	/*
	 * the following char array will be our outgoing packet.
	 * first, we'll calculate the length.
	 * the length consists of the following values:
	 * - length of header -> h2_pkt_header_len
	 * - length of command -> h2_pkt_servers_len
	 * - delimiter between command and list
	 * - number of servers in list
	 *   -> h2m.num_servers * 6
	 */

	// allocate memory for msg_out_length array
	// XXX: I don't know if there's any restriction in the h2m protocol
	//		regarding the # of servers or bytes sent to the client.
	//		I'll just leave it like this for now.
	h2m.msg_out_length = calloc(1, sizeof(int));
	if (h2m.msg_out_length == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(int));
		return -2; // TODO: define retval for errors
	}

	h2m.msg_out_length[0] = h2_pkt_header_len
					 + h2_pkt_servers_len
					 + (h2m.num_servers * 6);
	DEBUG("%d + %d + (%d * 6) = %d\n",
		h2_pkt_header_len, h2_pkt_servers_len,
		h2m.num_servers, h2m.msg_out_length[0]);

	// allocate memory for packet pointers
	h2m.msg_out = calloc(1, sizeof(char *));
	if (h2m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(char *));
		return -2; // TODO: define retval for errors
	}

	// allocate memory for the packet itself
	h2m.msg_out[0] = calloc(h2m.msg_out_length[0]+1, 1);
	if (h2m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				h2m.msg_out_length[0]+1);
		return -2; // TODO: define retval for errors
	}

	// copy h2_pkt_header into the packet
	memcpy(h2m.msg_out[0], h2_pkt_header, h2_pkt_header_len);
	memcpy(h2m.msg_out[0]+h2_pkt_header_len, h2_pkt_servers, h2_pkt_servers_len);
	msg_out_offset = h2_pkt_header_len + h2_pkt_servers_len;

	// create the packet
	for (i = 0; i < h2m.num_servers; i++) {
		// append ip and port to msg_out
		memcpy(h2m.msg_out[0]+msg_out_offset, &h2m.list[i].ip, 4);
		msg_out_offset += 4;
		memcpy(h2m.msg_out[0]+msg_out_offset, &h2m.list[i].port, 2);
		msg_out_offset += 2;
	}

	h2m.num_msgs = 1;

	// packet with server list is ready
	return 1;
} // process_query()

static int
process(char *packet, int packetlen)
{

	// check if packet is h2 related
	if (strncmp(packet, h2_pkt_header, h2_pkt_header_len) == 0) {
		DEBUG("H2 protocol marker detected!\n");
		// which packet did we receive?
		if (strncmp(packet+h2_pkt_header_len, h2_pkt_heartbeat, h2_pkt_heartbeat_len) == 0) {
			return process_heartbeat(packet);
		} else if (strncmp(packet+h2_pkt_header_len, h2_pkt_shutdown, h2_pkt_shutdown_len) == 0) {
			return process_shutdown(packet);
		} else if (strncmp(packet+h2_pkt_header_len, h2_pkt_ping, h2_pkt_ping_len) == 0) {
			return process_ping(packet);
		}
	} else if (strncmp(packet, h2_pkt_query, h2_pkt_query_len) == 0) {
		return process_query(packet);
	}
	return -1; // invalid packet
}

void
init_plugin(void)
{
	register_plugin(&h2m);
}

