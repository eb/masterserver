/* libd3.c: masterserver plugin for Doom 3 servers. */
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h> // for socket() etc.
#include <netinet/in.h>
#include <arpa/inet.h>
#include <math.h>

#include "../masterserver.h"

#define HEARTBEAT_TIMEOUT 300

// message of the day
#define D3M_MOTD "Insert MOTD here."

// for logging stuff
#undef LOG_SUBNAME
#define LOG_SUBNAME "libd3" // logging subcategory description

// d3 packet stuff
const char	d3_pkt_header[]		= "\xff\xff";
const int	d3_pkt_header_len	= 2;
const char	d3_pkt_heartbeat[]	= "heartbeat\0";
const int	d3_pkt_heartbeat_len= 10;
const char	d3_pkt_getinfo[]	= "getInfo\0\0\0\0\0";
const int	d3_pkt_getinfo_len	= 12;
const char	d3_pkt_inforsp[]	= "infoResponse";
const int	d3_pkt_inforsp_len	= 12;
const char	d3_pkt_getsrv[]		= "getServers";
const int	d3_pkt_getsrv_len	= 10;
const char	d3_pkt_getsrvrsp[]	= "servers\0";
const int	d3_pkt_getsrvrsp_len= 8;
const char	d3_pkt_verchk[]		= "versionCheck";
const int	d3_pkt_verchk_len	= 12;
const char	d3_pkt_srvauth[]	= "srvAuth";
const int	d3_pkt_srvauth_len	= 7;
const char	d3_pkt_delimiter[]	= "\0";

const char d3m_plugin_version[] = "0.1";
static port_t d3m_ports[] = { { IPPROTO_UDP, 27650 } };

// player info
// FIXME
typedef struct {
	int id;
	int ping;
	int rate;
	char *name;
} d3m_player_data_t;

// d3 plugin private data
typedef struct {
	int challenge;
	//int sv_punkbuster;	// 0 | 1
	char *fs_game;
	int si_maxPlayers; // max num of clients
	int si_timeLimit;
	int si_fragLimit;
	char *si_name; // server name
	char *si_version; // self explanatory
	char *si_gameType;	// deathmatch
	int protocol;	// d3 network protocol version
	char *si_map;	// self explanatory
	char *gamename;	// which mod
	int si_usepass;	// 0 | 1
	int si_warmup;
	int si_spectators;
	int si_teamDamage;
	int si_pure;
	d3m_player_data_t *_player; // player info
	// following is information not in packet
	int _players; // # of players
	int _challenge; // our challenge #
} d3m_private_data_t;

static void	info(void); // print information about plugin
static void	free_privdata(void *);
static int	process(char *, int); // process packet and return a value
static int	process_heartbeat(char *);
static int	process_getServers(char *);
static int	send_getInfo();
static int	process_infoResponse(char *, int);
static void	cleanup(void);
void		init_plugin(void) __attribute__ ((constructor)); 

static
struct masterserver_plugin d3m
= { "d3m",
	d3m_plugin_version,
	masterserver_version,
	d3m_ports,
	1,
	HEARTBEAT_TIMEOUT,
	&info,
	&process,
	//&free_privdata,
	NULL,
	&cleanup
};

static void
info(void)
{
	INFO("Doom 3 masterserver plugin v%s\n", d3m_plugin_version);
	INFO("  compiled for masterserver v%s\n", masterserver_version);
}

static void
free_privdata(void *data)
{
	//int i;
	d3m_private_data_t *privdata = (d3m_private_data_t *) data;

	if (data == NULL) return;

	free(privdata->fs_game);
	free(privdata->si_name);
	free(privdata->si_version);
	free(privdata->si_gameType);
	free(privdata->si_map);
	free(privdata->gamename);
	// FIXME
	/*for (i = 0; i < privdata->_players; i++)
	 *	free(privdata->_player[i].name);
	 *free(privdata->_player);
	 */
	// end FIXME
	free(privdata);
}

static int
process_heartbeat(char *packet)
{
	int server_dup = 0;
	int time_diff, i;
	serverlist_t *backup_ptr;

	// first, check if server is already in our list
	for (i = 0; i < d3m.num_servers; i++) {
		if ((d3m.list[i].ip.s_addr == d3m.client.sin_addr.s_addr)
				&& (d3m.list[i].port == d3m.client.sin_port)) {
			DEBUG("duplicate server detected! (%s:%d)\n",
					inet_ntoa(d3m.client.sin_addr), ntohs(d3m.client.sin_port));
			server_dup = 1;
			break;
		}
	}

	INFO("heartbeat from %s:%d\n",
			inet_ntoa(d3m.client.sin_addr), ntohs(d3m.client.sin_port));
	// if not, then add it to the list
	if (server_dup == 0) {
		// server is not in our list so add its ip, port and a timestamp
		d3m.list[d3m.num_servers].ip = d3m.client.sin_addr;
		d3m.list[d3m.num_servers].port = d3m.client.sin_port;
		d3m.list[d3m.num_servers].lastheartbeat = time(NULL);
		DEBUG("this is server no.: %d | lastheartbeat: %d\n",
				d3m.num_servers, d3m.list[d3m.num_servers].lastheartbeat);
		// allocate memory for private data
		d3m.list[d3m.num_servers].private_data = calloc(1, sizeof(d3m_private_data_t));

		d3m.num_servers++;

		DEBUG("reallocating server list (old size: %d -> new size: %d)\n",
				d3m.num_servers * sizeof(serverlist_t),
				(d3m.num_servers+1) * sizeof(serverlist_t));

		// back up the current list pointer in case realloc() fails
		backup_ptr = d3m.list;
		d3m.list = (serverlist_t *) realloc(d3m.list, ((d3m.num_servers+1)*sizeof(serverlist_t)));
		if (d3m.list == NULL) {
			WARNING("realloc() failed trying to get %d bytes!\n",
					(d3m.num_servers+1)*sizeof(serverlist_t));
			// since the pointer is overwritten with NULL
			// we'll recover by using the backup pointer
			d3m.list = backup_ptr;
			return -2;
		} else DEBUG("reallocation successful\n");
	} else {
		time_diff = time(NULL) - d3m.list[i].lastheartbeat;
		// if time_diff is 0 the server has shutdown (most likely)
		if (time_diff == 0) {
			INFO("server %s:%u is shutting down (time_diff %d)\n",
					inet_ntoa(d3m.list[i].ip), ntohs(d3m.list[i].port),
					time_diff);
			delete_server(&d3m, i);
			server_dup = 0;
			return 2; // return "server-shutdown" code
		} else {
			// server is in already in our list so we just update the timestamp
			d3m.list[i].lastheartbeat = time(NULL);
			server_dup = 0;
		}
	}
	// server added/updated
	return 1;
}

static int
send_getInfo()
{
	// prepare d3m.msg_out
	d3m.num_msgs = 1;
	d3m.msg_out_length = calloc(1, sizeof(int));
	if (d3m.msg_out_length == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", sizeof(int));
		return -2; // TODO: define retval for errors
	}
	DEBUG("allocated %d bytes for msg_out_length[]\n", sizeof(int));

	// d3m.msg_out_length[0] = d3_pkt_header_len + d3_pkt_getstatus_len;
	d3m.msg_out_length[0] = d3_pkt_header_len + d3_pkt_getinfo_len;

	// allocate the memory for the outgoing packet
	d3m.msg_out = calloc(1, sizeof(char *));
	if (d3m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", sizeof(char *));
		return -2; // TODO: define retval for errors
	}

	d3m.msg_out[0] = calloc(d3m.msg_out_length[0]+1, 1);
	if (d3m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				d3m.msg_out_length[0]);
		return -2; // TODO: define retval for errors
	}
	DEBUG("allocated %d bytes for msg_out[0]\n", d3m.msg_out_length[0]);

	memcpy(d3m.msg_out[0], d3_pkt_header, d3_pkt_header_len);
	memcpy(d3m.msg_out[0]+d3_pkt_header_len, d3_pkt_getinfo, d3_pkt_getinfo_len);

	return 1; // send "getInfo" packet
}

static int
process_getServers(char *packet)
{
	int i, pkt_offset; // temp vars
	int getsrv_protocol;
	char getsrv_filter;
	d3m_private_data_t *temp_priv_data;
	char **backup_ptr; // for recovery from realloc() failure

	INFO("getServers from %s:%u\n",
			inet_ntoa(d3m.client.sin_addr), ntohs(d3m.client.sin_port));

	// we need the protocol version from the packet so we parse it
	memcpy(&getsrv_protocol, packet+d3_pkt_header_len+d3_pkt_getsrv_len+1, 4);
	DEBUG("requested protocol is %d.%d (0x%08x)\n",
		getsrv_protocol >> 16, getsrv_protocol & 0xffff, getsrv_protocol);

	// parse the filter byte
	getsrv_filter = *(packet+d3_pkt_header_len+d3_pkt_getsrv_len+1+4+1);
	DEBUG("requested filter is 0x%02x\n", getsrv_filter);

	// got the protocol version now we can assemble the outgoing packet(s)
	DEBUG("assembling server list packet\n");

	d3m.num_msgs = 1;

	// allocate memory for the packets
	d3m.msg_out = malloc(sizeof(char*));
	if (d3m.msg_out == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n", sizeof(char*));
		return -2;
	}
	d3m.msg_out[0] = calloc(1, d3_pkt_header_len+d3_pkt_getsrvrsp_len+1);
	if (d3m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
			d3_pkt_header_len+d3_pkt_getsrvrsp_len+(d3m.num_servers*6));
		return -2;
	}

	d3m.msg_out_length = malloc(sizeof(int));
	if (d3m.msg_out_length == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n", sizeof(int));
		return -2;
	}
	d3m.msg_out_length[0] = d3_pkt_header_len+d3_pkt_getsrvrsp_len+1;

	// write header and command into packet
	memcpy(d3m.msg_out[0], d3_pkt_header, d3_pkt_header_len);
	pkt_offset = d3_pkt_header_len;
	memcpy(d3m.msg_out[0]+pkt_offset, d3_pkt_getsrvrsp, d3_pkt_getsrvrsp_len);
	pkt_offset += d3_pkt_getsrvrsp_len;
	// walk the server list
	for (i = 0; i < d3m.num_servers; i++) {
		temp_priv_data = (d3m_private_data_t *) d3m.list[i].private_data;
		// if the protocol matches, write ip/port into the packet
		if (temp_priv_data->protocol == getsrv_protocol) {
			backup_ptr = d3m.msg_out;
			d3m.msg_out[0] = realloc(d3m.msg_out[0], d3m.msg_out_length[0]+6);
			if (d3m.msg_out[0] == NULL) {
				ERRORV("realloc() failed trying to get %d bytes!\n",
					d3m.msg_out_length);
				WARNING("recovering ...\n");
				d3m.msg_out = backup_ptr;
				return 1;
			}
			// copy data from server list into packet
			memcpy(d3m.msg_out[0]+pkt_offset, &d3m.list[i].ip, 4);
			pkt_offset += 4;
			memcpy(d3m.msg_out[0]+pkt_offset, &d3m.list[i].port, 2);
			pkt_offset += 2;

			d3m.msg_out_length[0] += 6;
		}

	}

	d3m.msg_out[0][pkt_offset] = '\0';
	// XXX: fugly hack
	d3m.msg_out_length[0]--;
	DEBUG("d3m.msg_out_length[0] = %d (%d)\n", pkt_offset, d3m.msg_out_length[0]);

	// packet with server list is ready
	return 1;
}

static int
process_infoResponse(char *packet, int packetlen)
{
	char *varname = NULL, *value = NULL, *packetend = packet+packetlen;
	char *name = NULL;
	int offset = 0, temp_size, i;
	int server_dup = 0;
	short prediction;
	unsigned int rate;
	unsigned char player_id;
	d3m_private_data_t *private_data;
	d3m_private_data_t *oldprivdata;

	// check if source address is known
	for (i = 0; i < d3m.num_servers; i++) {
		if ((d3m.client.sin_addr.s_addr == d3m.list[i].ip.s_addr)
				&& (d3m.client.sin_port == d3m.list[i].port)) {
			server_dup = 1;
			break;
		}
	}

	// source address unknown
	if (server_dup == 0) {
		WARNING("unexpected \"infoResponse\" from %s:%d ignored\n",
				inet_ntoa(d3m.client.sin_addr), ntohs(d3m.client.sin_port));
		return -1;
	}

	oldprivdata = (d3m_private_data_t *)d3m.list[i].private_data;

	// allocate memory for private data
	private_data = calloc(1, sizeof(d3m_private_data_t));
	if (private_data == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
			sizeof(d3m_private_data_t));
		return -2;
	}

	// parse challenge and version
	packet += d3_pkt_header_len+d3_pkt_inforsp_len+1;
	memcpy(&private_data->challenge, packet, 4);
	packet += 4;
	memcpy(&private_data->protocol, packet, 4);

	DEBUG("challenge is %d\n", private_data->challenge);
	DEBUG("protocol is %d.%d (0x%x)\n",
		private_data->protocol >> 16, private_data->protocol & 0xffff,
		private_data->protocol);
	packet += 4;

	// begin parsing the server info
	DEBUG("begin parsing server info\n");
	while (packet < packetend)
	{
		varname = packet;
		value = strchr(packet, 0)+1;
		packet = strchr(value, 0)+1;

		// check if we're at the end of varname/value pairs
		if ((*value == '\0') && (*varname == '\0'))
			break;

		DEBUG("%s = %s\n", varname, value);

		// parse varname and assign the value to the struct
		if (strcmp(varname, "fs_game") == 0) {
			private_data->fs_game = strdup(value);
			if (private_data->fs_game == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				free_privdata(private_data);
				return -2;
			}
		} else if (strcmp(varname, "si_maxPlayers") == 0) {
			private_data->si_maxPlayers = atoi(value);
		} else if (strcmp(varname, "si_timeLimit") == 0) {
			private_data->si_timeLimit = atoi(value);
		} else if (strcmp(varname, "si_fragLimit") == 0) {
			private_data->si_fragLimit = atoi(value);
		} else if (strcmp(varname, "si_name") == 0) {
			private_data->si_name = strdup(value);
			if (private_data->si_name == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				free_privdata(private_data);
				return -2;
			}
		} else if (strcmp(varname, "si_version") == 0) {
			private_data->si_version = strdup(value);
			if (private_data->si_version == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				free_privdata(private_data);
				return -2;
			}
		} else if (strcmp(varname, "si_gameType") == 0) {
			private_data->si_gameType = strdup(value);
			if (private_data->si_gameType == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				free_privdata(private_data);
				return -2;
			}
		} else if (strcmp(varname, "si_map") == 0) {
			private_data->si_map = strdup(value);
			if (private_data->si_map == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				free_privdata(private_data);
				return -2;
			}
		} else if (strcmp(varname, "gamename") == 0) {
			private_data->gamename = strdup(value);
			if (private_data->gamename == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				free_privdata(private_data);
				return -2;
			}
		} else if (strcmp(varname, "si_usepass") == 0) {
			private_data->si_usepass = atoi(value);
		} else if (strcmp(varname, "si_warmup") == 0) {
			private_data->si_warmup = atoi(value);
		} else if (strcmp(varname, "si_spectators") == 0) {
			private_data->si_spectators = atoi(value);
		} else if (strcmp(varname, "si_teamDamage") == 0) {
			private_data->si_teamDamage = atoi(value);
		} else if (strcmp(varname, "si_pure") == 0) {
			private_data->si_pure = atoi(value);
		} else {
			WARNING("unknown option \"%s\" in statusResponse ignored\n", varname);
		}
	}
	DEBUG("end parsing server info\n");

	DEBUG("skipping player info\n");
	// parse player info
	// TODO
#if 0
	private_data->_players = 0;
	for (	player_id = *packet++;
			packet < packetend;
			player_id = *packet++)
	{
		if (player_id == 32) break;

		if (packet+7 > packetend) {
			WARNING("invalid infoResponse packet: player info too short\n");
			return -2;
		}

		memcpy(&prediction, packet, 2);
		packet += 2;

		memcpy(&rate, packet, 4);
		packet += 4;

		name = packet;
		if ((packet = memchr(packet, 0, packetend-packet)) == 0) {
			WARNING("invalid infoResponse packet: player name not null terminated\n");
			return -2;
		}
		packet++;

		// FIXME: recover from realloc() failure
		private_data->_player = (d3m_player_data_t *) realloc(private_data->_player,
				private_data->_players*sizeof(d3m_player_data_t));
		if (private_data->_player == NULL) {
			ERRORV("realloc() failed trying to get %d bytes!\n",
					private_data->_players*sizeof(d3m_player_data_t));
			return -2;
		}
		private_data->_player[private_data->_players].ping = prediction;
		private_data->_player[private_data->_players].name = strdup(name);
		DEBUG("name: \"%s\" ping: %d\n", prediction, name);
		private_data->_players++;
	}
#endif
	// TODO: osmask

	// compare challenge to ours
	if (private_data->challenge != oldprivdata->_challenge) {
		WARNING("statusResponse challenge mismatch (%d != %d)\n",
				private_data->challenge, oldprivdata->_challenge);
		free_privdata(private_data);
		return -1;
	}

	// if we already have parsed server/player info we have to free it first
	if (d3m.list[i].private_data != NULL) free_privdata(d3m.list[i].private_data);
	d3m.list[i].private_data = private_data;

	return 0;
}

static int
process(char *packet, int packetlen)
{
	int retval;

	// check if packet is Doom 3 related
	if (strncmp(packet, d3_pkt_header, d3_pkt_header_len) == 0) {
		DEBUG("Doom 3 protocol marker detected!\n");
		// which packet did we receive?
		if (strcmp(packet+d3_pkt_header_len, d3_pkt_heartbeat) == 0) {
			retval = process_heartbeat(packet);
			if (retval == 1) {
				send_getInfo();
				return 1; // "send packet" code
			}
			return retval;
		} else if (strncmp(packet+d3_pkt_header_len, d3_pkt_getsrv, d3_pkt_getsrv_len) == 0) {
			return process_getServers(packet);
		} else if (strncmp(packet+d3_pkt_header_len, d3_pkt_inforsp, d3_pkt_inforsp_len) == 0) {
			return process_infoResponse(packet, packetlen);
		} else if (strncmp(packet+d3_pkt_header_len, d3_pkt_verchk, d3_pkt_verchk_len) == 0) {
			DEBUG("STUB: process_versionCheck()\n");
			//return process_versionCheck(packet, packetlen);
		} else if (strncmp(packet+d3_pkt_header_len, d3_pkt_srvauth, d3_pkt_srvauth_len) == 0) {
			DEBUG("STUB: process_srvAuth()\n");
			//return process_srvAuth(packet, packetlen);
		}
		WARNING("unknown packet received!\n");
		return -1;
	} // end if for 0xffff marker
	WARNING("invalid packet received: Doom 3 protocol marker missing!\n");
	return -1; // invalid packet
}

static void
cleanup(void)
{
	int i;

	if (d3m.num_servers > 0) {
		for (i = 0; i < d3m.num_servers; i++) {
			free_privdata(d3m.list[i].private_data);
		}
	}
}

void
init_plugin(void)
{
	register_plugin(&d3m);
}

