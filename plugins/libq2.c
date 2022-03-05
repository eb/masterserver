/* libq2.c: masterserver plugin for Quake2 servers. */
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
#define LOG_SUBNAME "libq2" // logging subcategory description

const char	q2_pkt_header[]		= "\xff\xff\xff\xff";
const int	q2_pkt_header_len	= 4;
// we just check for the keyword
const char	q2_pkt_heartbeat[]	= "heartbeat";
const int	q2_pkt_heartbeat_len= 9;
const char	q2_pkt_query[]		= "query";
const int	q2_pkt_query_len	= 5;
const char	q2_pkt_servers[]	= "servers ";
const int	q2_pkt_servers_len	= 8;
const char	q2_pkt_shutdown[]	= "shutdown";
const int	q2_pkt_shutdown_len	= 8;
const char	q2_pkt_ping[]		= "ping";
const int	q2_pkt_ping_len		= 4;
const char	q2_pkt_ack[]		= "ack";
const int	q2_pkt_ack_len		= 3;

const char q2m_plugin_version[] = "0.4";
static port_t q2m_ports[] = { { IPPROTO_UDP, 27900 } };

static void	info(void); // print information about plugin
static int	process(char *, int); // process packet and return a value
static int	process_heartbeat(char *);
static int	process_shutdown(char *);
static int	process_ping(char *);
static int	process_query(char *);
void		init_plugin(void) __attribute__ ((constructor));

static
struct masterserver_plugin q2m
= { "q2m",
	q2m_plugin_version,
	masterserver_version,
	q2m_ports,
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
	INFO("quake2 masterserver plugin v%s\n", q2m_plugin_version);
	INFO("  compiled for masterserver v%s\n", masterserver_version);
}

static int
process_heartbeat(char *packet)
{
	int i, server_dup = 0, time_diff; // temp vars

	// first, check if server is already in our list
	for (i = 0; i < q2m.num_servers; i++) {
		if ((q2m.list[i].ip.s_addr == q2m.client.sin_addr.s_addr)
				&& (q2m.list[i].port == q2m.client.sin_port)) {
			DEBUG("duplicate server detected! (%s:%d)\n",
				inet_ntoa(q2m.client.sin_addr), ntohs(q2m.client.sin_port));
			server_dup = 1;
			break;
		}
	}

	INFO("heartbeat from %s:%d\n",
			inet_ntoa(q2m.client.sin_addr), ntohs(q2m.client.sin_port));
	// if not, then add it to the list
	if (!server_dup) {
		q2m.list[q2m.num_servers].ip = q2m.client.sin_addr;
		q2m.list[q2m.num_servers].port = q2m.client.sin_port;
		q2m.list[q2m.num_servers].lastheartbeat = time(NULL);
		q2m.num_servers++;

		DEBUG("reallocating server list (old size: %d -> new size: %d)\n",
			q2m.num_servers * sizeof(serverlist_t),
			(q2m.num_servers+1) * sizeof(serverlist_t));

		q2m.list = realloc(q2m.list, ((q2m.num_servers + 1) * sizeof(serverlist_t)));
		if (q2m.list == NULL) {
			ERRORV("realloc() failed trying to get %d bytes!\n",
					(q2m.num_servers+1)*sizeof(serverlist_t));
			pthread_exit((void *) -1);
		} else DEBUG("reallocation successful\n");
	} else {
		time_diff = time(NULL) - q2m.list[i].lastheartbeat;
		// server is in already in our list so we just update the timestamp
		q2m.list[i].lastheartbeat = time(NULL);
		server_dup = 0;
	}
	return 0; // server added to list
} // process_heartbeat()

static int
process_shutdown(char *packet)
{
	int i, time_diff, server_dup = 0;

	// check if the server is in our list
	for (i = 0; i < q2m.num_servers; i++) {
		if ((q2m.list[i].ip.s_addr == q2m.client.sin_addr.s_addr)
				&& (q2m.list[i].port == q2m.client.sin_port)) {
			server_dup = 1;
			break;
		}
	}

	// if yes, remove it
	if (server_dup) {
		time_diff = time(NULL) - q2m.list[i].lastheartbeat;
		INFO("server %s:%u is shutting down (time_diff %d)\n",
			inet_ntoa(q2m.list[i].ip), ntohs(q2m.list[i].port), time_diff);
		delete_server(&q2m, i);
		return 2; // return "server shutdown" code
	} else return -1; // invalid packet
} // process_shutdown()

static int
process_ping(char *packet)
{
	INFO("ping from %s:%d\n", inet_ntoa(q2m.client.sin_addr), ntohs(q2m.client.sin_port));
	// allocate memory for msg_out_length array
	q2m.msg_out_length = calloc(1, sizeof(int));
	if (q2m.msg_out_length == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(int));
		return -2;
	}

	// calculate length of packet
	q2m.msg_out_length[0] = q2_pkt_header_len + q2_pkt_ack_len;

	// allocate memory for packet pointers (we only send 1)
	q2m.msg_out = calloc(1, sizeof(char *));
	if (q2m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(char *));
		return -2;
	}

	// allocate memory for the packet itself
	q2m.msg_out[0] = calloc(q2m.msg_out_length[0]+1, 1);
	if (q2m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				q2m.msg_out_length[0]+1);
		return -2;
	}

	// write packet contents
	memcpy(q2m.msg_out[0], q2_pkt_header, q2_pkt_header_len);
	memcpy(q2m.msg_out[0]+q2_pkt_header_len, q2_pkt_ack, q2_pkt_ack_len);

	q2m.num_msgs = 1;

	return 1; // tell masterserver to send it out
} // process_ping()

static int
process_query(char *packet)
{
	int i; // temp vars
	int msg_out_offset; // temp var for keeping track of where were writing the outgoing packet

	INFO("query from %s:%d\n",
		inet_ntoa(q2m.client.sin_addr), ntohs(q2m.client.sin_port));

	/*
	 * the following char array will be our outgoing packet.
	 * first, we'll calculate the length.
	 * the length consists of the following values:
	 * - length of header -> q2_pkt_header_len
	 * - length of command -> q2_pkt_servers_len
	 * - delimiter between command and list
	 * - number of servers in list -> q2m.num_servers * 6
	 */

	// allocate memory for msg_out_length array
	// XXX: I don't know if there's any restriction in the q2m protocol
	//		regarding the # of servers or bytes sent to the client.
	//		I'll just leave it like this for now.
	q2m.msg_out_length = calloc(1, sizeof(int));
	if (q2m.msg_out_length == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(int));
		return -2; // TODO: define retval for errors
	}

	q2m.msg_out_length[0] = q2_pkt_header_len
					 + q2_pkt_servers_len
					 + (q2m.num_servers * 6);
	DEBUG("%d + %d + (%d * 6) = %d\n",
		q2_pkt_header_len, q2_pkt_servers_len,
		q2m.num_servers, q2m.msg_out_length[0]);

	// allocate memory for packet pointers
	q2m.msg_out = calloc(1, sizeof(char *));
	if (q2m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(char *));
		return -2; // TODO: define retval for errors
	}

	// allocate memory for the packet itself
	q2m.msg_out[0] = calloc(q2m.msg_out_length[0]+1, 1);
	if (q2m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				q2m.msg_out_length[0]+1);
		return -2; // TODO: define retval for errors
	}

	// copy q2_pkt_header into the packet
	memcpy(q2m.msg_out[0], q2_pkt_header, q2_pkt_header_len);
	memcpy(q2m.msg_out[0]+q2_pkt_header_len, q2_pkt_servers, q2_pkt_servers_len);
	msg_out_offset = q2_pkt_header_len + q2_pkt_servers_len;

	// create the packet
	for (i = 0; i < q2m.num_servers; i++) {
		// append ip and port to msg_out
		memcpy(q2m.msg_out[0]+msg_out_offset, &q2m.list[i].ip, 4);
		msg_out_offset += 4;
		memcpy(q2m.msg_out[0]+msg_out_offset, &q2m.list[i].port, 2);
		msg_out_offset += 2;
	}

	q2m.num_msgs = 1;

	// return status 1
	// packet with server list is ready
	return 1;
} // process_query()


static int
process(char *packet, int packetlen)
{
	// check if packet is q2 related
	if (strncmp(packet, q2_pkt_header, q2_pkt_header_len) == 0) {
		DEBUG("Q2 protocol marker detected!\n");
		// which packet did we receive?
		if (strncmp(packet+q2_pkt_header_len, q2_pkt_heartbeat, q2_pkt_heartbeat_len) == 0) {
			return process_heartbeat(packet);
		} else if (strncmp(packet+q2_pkt_header_len, q2_pkt_shutdown, q2_pkt_shutdown_len) == 0) {
			return process_shutdown(packet);
		} else if (strncmp(packet+q2_pkt_header_len, q2_pkt_ping, q2_pkt_ping_len) == 0) {
			return process_ping(packet);
		}
	} else if (strncmp(packet, q2_pkt_query, q2_pkt_query_len) == 0) {
		return process_query(packet);
	}
	return -1; // invalid packet
}

void
init_plugin(void)
{
	register_plugin(&q2m);
}

