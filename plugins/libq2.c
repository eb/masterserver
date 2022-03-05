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
 * The author can be contacted at andre@malchen.de
 */

#include "../masterserver.h"

// for future use
// #define Q2M_PROTOCOL IPPROTO_UDP
#define Q2M_PLUGIN_VERSION_MAJOR 0
#define Q2M_PLUGIN_VERSION_MINOR 3
#define HEARTBEAT_TIMEOUT 300

#undef LOG_SUBNAME
#define LOG_SUBNAME "libq2" // logging subcategory description

const char	q2_pkt_header[]		= "\xff\xff\xff\xff";
const int	q2_pkt_header_len	= 4;
// we just check for the keyword
const char	q2_pkt_heartbeat[]	= "heartbeat";
const int	q2_pkt_heartbeat_len= 9;
const char	q2_pkt_query[]		= "query\n\0";
const int	q2_pkt_query_len	= 7;
const char	q2_pkt_servers[]	= "servers ";
const int	q2_pkt_servers_len	= 8;
const char	q2_pkt_shutdown[]	= "shutdown";
const int	q2_pkt_shutdown_len	= 8;
const char	q2_pkt_ping[]		= "ping";
const int	q2_pkt_ping_len		= 4;
const char	q2_pkt_ack[]		= "ack";
const int	q2_pkt_ack_len		= 3;

// FIXME: either kill this or try to create it from the macros above
const char q2m_plugin_version[] = "0.3";
static int q2m_ports[] = { 27900 };

static void info(void); // print information about plugin
static int process(char *packet); // process packet and return a value
static int process_heartbeat(char *packet);
static int process_shutdown(char *packet);
static int process_ping(char *packet);
static int process_query(char *packet);


static
struct masterserver_plugin q2m
= { "q2m",
	q2m_plugin_version,
	masterserver_version,
	q2m_ports,
	1,
	// Q2M_PROTOCOL, // for future use
	HEARTBEAT_TIMEOUT,
	&info,
	&process,
	NULL
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

	// if not, then add it to the list
	if (server_dup == 0) {
		q2m.list[q2m.num_servers].ip = q2m.client.sin_addr;
		q2m.list[q2m.num_servers].port = q2m.client.sin_port;
		q2m.list[q2m.num_servers].lastheartbeat = time(NULL);
		INFO("Heartbeat from %s:%u; added to server list\n",
			inet_ntoa(q2m.client.sin_addr), ntohs(q2m.client.sin_port));
		q2m.num_servers++;

		DEBUG("reallocating server list (old size: %d -> new size: %d)\n",
			q2m.num_servers * sizeof(serverlist_t),
			(q2m.num_servers+1) * sizeof(serverlist_t));
		if (q2m.num_servers > 0)
			q2m.list = realloc(q2m.list, ((q2m.num_servers + 1) * sizeof(serverlist_t)));
		if (q2m.list == NULL) {
			ERROR("can't increase q2m.list size; out of memory!\n");
			pthread_exit((void *) -1);
		} else DEBUG("reallocation successful\n");
	} else {
		time_diff = time(NULL) - q2m.list[i].lastheartbeat;
		// server is in already in our list so we just update the timestamp
		INFO("heartbeat from %s:%d; already in server list; updating timestamp (time_diff %d)\n",
			inet_ntoa(q2m.list[i].ip), ntohs(q2m.list[i].port), time_diff);
		q2m.list[i].lastheartbeat = time(NULL);
		server_dup = 0;
	}
	return 0; // server added to list
} // process_heartbeat()

static int
process_shutdown(char *packet)
{
	int i, time_diff;

	// sanity check num_servers
	// FIXME: wtf did I think I was doing here?!
	for (i = 0; i < q2m.num_servers; i++) {
		if ((q2m.list[i].ip.s_addr == q2m.client.sin_addr.s_addr)
				&& (q2m.list[i].port == q2m.client.sin_port))
			break;
	}

	if ((i >= 0) && (i != q2m.num_servers)) {
		time_diff = time(NULL) - q2m.list[i].lastheartbeat;
		INFO("server %d (%s:%u) is shutting down. bye, bye. (time_diff %d)\n",
			i, inet_ntoa(q2m.list[i].ip), ntohs(q2m.list[i].port), time_diff);
		delete_server(&q2m, i);
		return 2; // return "server shutdown" code
	} else return -1; // invalid packet
} // process_shutdown()

static int
process_ping(char *packet)
{
	char **msg_out = NULL; // pointer to outgoing packet
	int *msg_out_length; // length of outgoing packet

	INFO("ping from %s:%d\n", inet_ntoa(q2m.client.sin_addr), ntohs(q2m.client.sin_port));
	// allocate memory for msg_out_length array
	msg_out_length = calloc(1, sizeof(int));

	// calculate length of packet
	msg_out_length[0] = q2_pkt_header_len + q2_pkt_ack_len;

	// allocate memory for packet pointers (we only send 1)
	msg_out = calloc(1, sizeof(char *));

	// allocate memory for the packet itself
	msg_out[0] = calloc(msg_out_length[0]+1, sizeof(char));

	// write packet contents
	snprintf(msg_out[0], msg_out_length[0]+2, "%s%s", q2_pkt_header, q2_pkt_ack);

	// feed the information to masterserver
	q2m.msg_out = msg_out;
	q2m.msg_out_length = msg_out_length;
	q2m.num_msgs = 1;
	return 1; // tell masterserver to send it out
} // process_ping()

static int
process_query(char *packet)
{
	int i; // temp vars
	unsigned char *ip, *port; // temp vars for creating outgoing packets
	char **msg_out = NULL; // pointer to outgoing packet
	int msg_out_offset; // temp var for keeping track of where were writing the outgoing packet
	int *msg_out_length; // length of outgoing packet

	INFO("query from %s:%d\n",
		inet_ntoa(q2m.client.sin_addr), ntohs(q2m.client.sin_port));

	/*
	 * the following char array will be our outgoing packet.
	 * first, we'll calculate the length.
	 * the length consists of the following values:
	 * - length of header -> q2_pkt_header_len
	 * - length of command -> q2_pkt_servers_len
	 * - delimiter between command and list
	 * - number of servers in list
	 *   -> q2m.num_servers * (sizeof(q2m.list[0].ip) + sizeof(q2m.list[0].port))
	 */

	// allocate memory for msg_out_length array
	// XXX: I don't know if there's any restriction in the q2m protocol
	//		regarding the # of servers or bytes sent to the client.
	//		I'll just leave it like this for now.
	msg_out_length = calloc(1, sizeof(int));
	if (msg_out_length == NULL) {
		ERROR("couldn't allocate memory for outgoing udp packet!\n");
		return -2; // TODO: define retval for errors
	}

	msg_out_length[0] = q2_pkt_header_len
					 + q2_pkt_servers_len
					 + (q2m.num_servers * (sizeof(q2m.list[0].ip) + sizeof(q2m.list[0].port)));
	DEBUG("%d + %d + 1 + (%d * (%d + %d)) = %d\n",
		q2_pkt_header_len, q2_pkt_servers_len,
		q2m.num_servers, sizeof(q2m.list[0].ip), sizeof(q2m.list[0].port),
		msg_out_length[0]);

	// allocate memory for packet pointers
	msg_out = calloc(1, sizeof(char *));
	if (msg_out == NULL) {
		ERROR("couldn't allocate memory for outgoing udp packet!\n");
		return -2; // TODO: define retval for errors
	}

	// allocate memory for the packet itself
	msg_out[0] = calloc(msg_out_length[0]+1, sizeof(char));
	if (msg_out == NULL) {
		ERROR("couldn't allocate memory for outgoing udp packet!\n");
		return -2; // TODO: define retval for errors
	}

	// copy q2_pkt_header into the packet
	snprintf(msg_out[0], q2_pkt_header_len+1, "%s", q2_pkt_header);
	snprintf(msg_out[0]+q2_pkt_header_len, q2_pkt_servers_len+1, "%s", q2_pkt_servers);
	msg_out_offset = q2_pkt_header_len + q2_pkt_servers_len;

	// create the packet
	for (i = 0; i < q2m.num_servers; i++) {
		// put ip and port in char arrays
		// XXX: I'm not sure if this is sane ...
		ip = (unsigned char *) &q2m.list[i].ip;
		port = (unsigned char *) &q2m.list[i].port;

		// append ip and port to msg_out
		snprintf(msg_out[0]+msg_out_offset, 6+1, "%c%c%c%c%c%c",
			ip[0], ip[1], ip[2], ip[3], port[0], port[1]);

		msg_out_offset += 6;
	}

	// let the masterserver know where the packet is
	q2m.msg_out = msg_out;
	q2m.msg_out_length = msg_out_length;
	q2m.num_msgs = 1;

	// return status 1
	// packet with server list is ready
	return 1;
} // process_query()


static int
process(char *packet)
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
	} else if (strcmp(packet, q2_pkt_query) == 0) {
		return process_query(packet);
	}
	return -1; // invalid packet
}

void
_init(void)
{
	register_plugin(&q2m);
}

