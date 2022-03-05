/* libqw.c: masterserver plugin for QuakeWorld servers. */
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
// #define QWM_PROTOCOL IPPROTO_UDP

#define HEARTBEAT_TIMEOUT 300

// for logging stuff
#undef LOG_SUBNAME
#define LOG_SUBNAME "libqw" // logging subcategory description

// qw packet stuff
// many thanks go to id software and quakeforge
const char	qw_pkt_header[]		= "\xff\xff\xff\xff";
const int	qw_pkt_header_len	= 4;
const char	qw_pkt_heartbeat[]	= "a"; // more data
const int	qw_pkt_heartbeat_len= 1;
const char	qw_pkt_shutdown[]	= "C";
const int	qw_pkt_shutdown_len	= 1;
const char	qw_pkt_slistreq[]	= "c";
const int	qw_pkt_slistreq_len	= 1;
const char	qw_pkt_slistrep[]	= "d\n"; // more data
const int	qw_pkt_slistrep_len	= 2;
const char	qw_pkt_ping[]		= "k";
const int	qw_pkt_ping_len		= 1;
const char	qw_pkt_ack[]		= "l";
const int	qw_pkt_ack_len		= 1;
const char	qw_pkt_nack[]		= "m";
const int	qw_pkt_nack_len		= 1;

// extended stuff
/*
const char	qw_pkt_connreq[]	= "b\n%s\n%s\n%s\n"; // connection request
const int	qw_pkt_connreq_len	= 2;
const char	qw_pkt_nuser_req[]	= "e\n%s\n"; // new user
const int	qw_pkt_nuser_req_len= 2;
const char	qw_pkt_nuser_rep[]	= "f\n%d"; // new user reply
const int	qw_pkt_nuser_rep_len= 2;
const char	qw_pkt_connreqs[]	= "i\n%s:%d\n%d\n%s\n";
const int	qw_pkt_connreqs_len	= 2;
const char	qw_pkt_userp_req[]	= "o\n%s\n%s";
const int	qw_pkt_userp_req_len= 2;
const char	qw_pkt_userp_rep[]	= "p\n\\*userid\\%d%s";
const int	qw_pkt_userp_rep_len= 2;
const char	qw_pkt_setinfo[]	= "r\n%s\n%s\n%s\n%s\n";
const int	qw_pkt_setinfo_len	= 2;
const char	qw_pkt_seen_req[]	= "u\n%s\n";
const int	qw_pkt_seen_req_len	= 2;
const char	qw_pkt_seen_rep[]	= "v\n%s";
const int	qw_pkt_seen_rep_len	= 2;
const char	qw_pkt_clientcmd[]	= "B"; // more data
const int	qw_pkt_clientcmd_len= 1;
const char	qw_pkt_print[]		= "n"; // more data
const int	qw_pkt_print_len	= 1;
const char	qw_pkt_echo[]		= "e"; // more data?
const int	qw_pkt_echo_len		= 1;
*/

const char qwm_plugin_version[] = "0.1.1";
static int qwm_ports[] = { 27000 };

// player info
typedef struct {
	int score;
	int ping;
	char *name;
} qwm_player_data_t;

// q3 plugin private data
typedef struct {
	// statusResponse vars
	int fraglimit;
	int timelimit;
	int teamplay;
	int samelevel;
	int maxspectators;
	int deathmatch;
	int spawn;
	int watervis;
	char *version;
	char *progs;

	qwm_player_data_t *_player; // player info
	// following is information not in packet
	int _players; // # of players
	// TODO: what about custom cvars (Administrator, ...) ?
} qwm_private_data_t;

static void info(void); // print information about plugin
static int process(char *packet); // process packet and return a value
static int process_heartbeat(char *packet);
static int process_slistreq();
static int process_ping();
static int process_shutdown();
static void cleanup(void);
void init_plugin(void) __attribute__ ((constructor));

static
struct masterserver_plugin qwm
= { "qwm",
	qwm_plugin_version,
	masterserver_version,
	qwm_ports,
	1,
//	QWM_PROTOCOL, // for future use
	HEARTBEAT_TIMEOUT,
	&info,
	&process,
	&cleanup
};

static void
info(void)
{
	INFO("quakeworld masterserver plugin v%s\n", qwm_plugin_version);
	INFO("  compiled for masterserver v%s\n", masterserver_version);
}

static int
process_heartbeat(char *packet)
{
	int server_dup = 0;
	int time_diff, i;

	// first, check if server is already in our list
	for (i = 0; i < qwm.num_servers; i++) {
		if ((qwm.list[i].ip.s_addr == qwm.client.sin_addr.s_addr)
				&& (qwm.list[i].port == qwm.client.sin_port)) {
			DEBUG("duplicate server detected! (%s:%d)\n",
					inet_ntoa(qwm.client.sin_addr), ntohs(qwm.client.sin_port));
			server_dup = 1;
			break;
		}
	}

	INFO("heartbeat from %s:%u\n",
			inet_ntoa(qwm.client.sin_addr), ntohs(qwm.client.sin_port));
	// if not, then add it to the list
	if (!server_dup) {
		qwm.list[qwm.num_servers].ip = qwm.client.sin_addr;
		qwm.list[qwm.num_servers].port = qwm.client.sin_port;
		qwm.list[qwm.num_servers].lastheartbeat = time(NULL);
		DEBUG("this is server no.: %d | lastheartbeat: %d\n",
				qwm.num_servers, qwm.list[qwm.num_servers].lastheartbeat);
		// allocate memory for private data
		// XXX: disabled for now
		//qwm.list[qwm.num_servers].private_data = calloc(1, sizeof(qwm_private_data_t));

		qwm.num_servers++;

		DEBUG("reallocating server list (old size: %d -> new size: %d)\n",
				qwm.num_servers * sizeof(serverlist_t),
				(qwm.num_servers+1) * sizeof(serverlist_t));
		qwm.list = (serverlist_t *) realloc(qwm.list, ((qwm.num_servers+1)*sizeof(serverlist_t)));
		if (qwm.list == NULL) {
			//WARNING("can't increase qwm.list size; out of memory!\n");
			ERRORV("realloc() failed trying to get %d bytes!\n",
					(qwm.num_servers+1)*sizeof(serverlist_t));
			// since the pointer is overwritten with NULL
			// we can't recover; so just exit here
			// XXX: maybe save the old pointer somewhere so
			//		we can continue?
			// FIXME: don't pthread_exit() here instead return -3 or so
			pthread_exit((void *) -1);
		} else DEBUG("reallocation successful\n");
	} else {
		time_diff = time(NULL) - qwm.list[i].lastheartbeat;
		// server is in already in our list so we just update the timestamp
		qwm.list[i].lastheartbeat = time(NULL);
	}
	// server added/updated
	return 0;
}

static int
process_slistreq()
{
	int i, pkt_offset, pkt_servers = 0; // temp vars
	//qwm_private_data_t *temp_priv_data;

	INFO("slist_req from %s:%u\n",
			inet_ntoa(qwm.client.sin_addr), ntohs(qwm.client.sin_port));

	/*
	 * This is the new, badly documented packet assembler.
	 */
	qwm.msg_out = malloc(sizeof(char *));
	if (qwm.msg_out == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n", sizeof(char *));
		return -2;
	}

	qwm.msg_out_length = malloc(sizeof(int));
	if (qwm.msg_out_length == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n", sizeof(int));
		return -2;
	}

	qwm.msg_out_length[0] = qw_pkt_header_len+qw_pkt_slistrep_len
			+(qwm.num_servers*6);

	// get memory for header and command
	qwm.msg_out[0] = calloc(qwm.msg_out_length[0]+1,sizeof(char));
	if (qwm.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				(qwm.msg_out_length[0]+1)*sizeof(char));
		return -2;
	}

	DEBUG("assembling server list packet\n");

	// write header and command into packet
	memcpy(qwm.msg_out[0], qw_pkt_header, qw_pkt_header_len);
	pkt_offset = qw_pkt_header_len;
	memcpy(qwm.msg_out[0]+pkt_offset, qw_pkt_slistrep, qw_pkt_slistrep_len);
	pkt_offset += qw_pkt_slistrep_len;

	for (i = 0; i < qwm.num_servers; i++) {
		//temp_priv_data = (qwm_private_data_t *) qwm.list[i].private_data;
		DEBUG("pkt_offset: %d\n", pkt_offset);

		// copy data from server list into packet
		memcpy(qwm.msg_out[0]+pkt_offset, &qwm.list[i].ip, 4);
		pkt_offset += 4;
		memcpy(qwm.msg_out[0]+pkt_offset, &qwm.list[i].port, 2);
		pkt_offset += 2;
		pkt_servers++;
	}

	DEBUG("pkt_offset: %d\n", pkt_offset);
	qwm.num_msgs = 1;

	// packet with server list is ready
	return 1;
}

static int
process_ping()
{
	INFO("ping from %s:%u\n",
			inet_ntoa(qwm.client.sin_addr), ntohs(qwm.client.sin_port));

	// prepare qwm.msg_out
	qwm.num_msgs = 1;
	qwm.msg_out_length = calloc(1, sizeof(int));
	if (qwm.msg_out_length == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", sizeof(int));
		return -2; // TODO: define retval for errors
	}
	DEBUG("allocated %d bytes for msg_out_length[]\n", sizeof(int));

	qwm.msg_out_length[0] = qw_pkt_header_len + qw_pkt_ack_len;

	// allocate the memory for the outgoing packet
	qwm.msg_out = calloc(1, sizeof(char *));
	if (qwm.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", sizeof(char *));
		return -2; // TODO: define retval for errors
	}

	qwm.msg_out[0] = calloc(qwm.msg_out_length[0]+1, sizeof(char));
	if (qwm.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				(qwm.msg_out_length[0]+1)*sizeof(char));
		return -2; // TODO: define retval for errors
	}
	DEBUG("allocated %d bytes for msg_out[0]\n", qwm.msg_out_length[0]);

	memcpy(qwm.msg_out[0], qw_pkt_header, qw_pkt_header_len);
	memcpy(qwm.msg_out[0]+qw_pkt_header_len, qw_pkt_ack, qw_pkt_ack_len);

	return 1; // send "ack" packet
}

static int
process_shutdown()
{
	int i, time_diff, server_dup = 0;

	for (i = 0; i < qwm.num_servers; i++) {
		if ((qwm.list[i].ip.s_addr == qwm.client.sin_addr.s_addr)
				&& (qwm.list[i].port == qwm.client.sin_port)) {
			server_dup = 1;
			break;
		}
	}

	if (server_dup) {
		time_diff = time(NULL) - qwm.list[i].lastheartbeat;
		INFO("%s:%u is shutting down (time_diff %d)\n",
			inet_ntoa(qwm.list[i].ip), ntohs(qwm.list[i].port), time_diff);
		delete_server(&qwm, i);
		return 2; // return "server shutdown" code
	} else return -1; // invalid packet
} // process_shutdown()



static int
process(char *packet)
{
	switch(packet[0]) {
		// which packet did we receive?
		case 'a':
			return process_heartbeat(packet);
			break;
		case 'c':
			return process_slistreq();
			break;
		case 'k':
			return process_ping();
			break;
		case 'C':
			return process_shutdown();
			break;
		default:
			WARNING("unknown packet received!\n");
			return -1;
	} // end switch()
}

static void
cleanup(void)
{
	/*
	int i, j;
	qwm_private_data_t *tmp_privdata;

	if (qwm.num_servers > 0) {
		for (i = 0; i < qwm.num_servers; i++) {
			tmp_privdata = (qwm_private_data_t *) qwm.list[i].private_data;
			for (j = 0; j < tmp_privdata->_players; j++)
				free(tmp_privdata->_player[j].name);
			free(tmp_privdata->_player);
			free(tmp_privdata->version);
			free(tmp_privdata->mapname);
			free(tmp_privdata->gamename);
			free(tmp_privdata->sv_hostname);
			free(tmp_privdata);
			free(qwm.list[i].private_data);
		}
	}*/
}

void
init_plugin(void)
{
	register_plugin(&qwm);
}

