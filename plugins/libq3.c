/* libq3.c: masterserver plugin for Quake3 servers. */
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
#define Q3M_MOTD "Insert MOTD here."

// for logging stuff
#undef LOG_SUBNAME
#define LOG_SUBNAME "libq3" // logging subcategory description

// q3 packet stuff
const char	q3_pkt_header[]		= "\xff\xff\xff\xff";
const int	q3_pkt_header_len	= 4;
const char	q3_pkt_heartbeat[]	= "heartbeat QuakeArena-1\n";
const int	q3_pkt_heartbeat_len= 23;
const char	q3_pkt_getinfo[]	= "getinfo\n";
const int	q3_pkt_getinfo_len	= 8;
const char	q3_pkt_inforsp[]	= "infoResponse\n";
const int	q3_pkt_inforsp_len	= 13;
const char	q3_pkt_getstatus[]	= "getstatus ";
const int	q3_pkt_getstatus_len= 10;
const char	q3_pkt_statusrsp[]	= "statusResponse\n";
const int	q3_pkt_statusrsp_len= 15;
const char	q3_pkt_getsrv[]		= "getservers";
const int	q3_pkt_getsrv_len	= 10;
const char	q3_pkt_getsrvrsp[]	= "getserversResponse";
const int	q3_pkt_getsrvrsp_len= 18;
const char	q3_pkt_getmotd[]	= "getmotd";
const int	q3_pkt_getmotd_len	= 7;
const char	q3_pkt_motd[]		= "\xff\xff\xff\xffmotd \"challenge\\%d\\motd\\%s\\\"";
const int	q3_pkt_motd_len		= 28;
const char	q3_pkt_footer[]		= "\\EOT";
const int	q3_pkt_footer_len	= 4;

const char q3m_plugin_version[] = "0.8";
static port_t q3m_ports[] = {	{ IPPROTO_UDP, 27950 },	// master
								{ IPPROTO_UDP, 27951 },	// motd
								// { IPPROTO_UDP, 27952 }, // auth
							};

// player info
typedef struct {
	int score;
	int ping;
	char *name;
} q3m_player_data_t;

// q3 plugin private data
typedef struct {
	// statusResponse vars
	int challenge;
	int sv_punkbuster;	// 0 | 1
	int g_maxGameClients;
	int capturelimit;
	int sv_maxclients;	// max num of clients
	int timelimit;
	int fraglimit;
	int dmflags;		// bit field
	int sv_maxPing;
	int sv_minPing;
	char *sv_hostname;	// server name
	int sv_maxRate;
	int sv_floodProtect; // 0 | 1
	char *version;	// self explanatory
	int g_gametype;	// 0 - FFA | 1 - Tournament | 2 - Single Player | 3 - TDM | 4 - CTF
	int protocol;	// q3 network protocol version
	char *mapname;	// self explanatory
	int sv_privateClients;	// # of passworded player slots
	int sv_allowDownload;	// 0 | 1
	int bot_minplayers;
	char *gamename;	// which mod
	int g_needpass;	// 0 | 1
	q3m_player_data_t *_player; // player info
	// following is information not in packet
	int _players; // # of players
	int _challenge; // our challenge #
} q3m_private_data_t;

static void	info(void); // print information about plugin
static void	free_privdata(void *);
static int	process(char *, int); // process packet and return a value
static int	process_getmotd(char *, int);
static int	process_getservers(char *);
static int	process_heartbeat(char *);
static int	send_getstatus();
static int	process_statusResponse(char *, int);
static void	cleanup(void);
void		init_plugin(void) __attribute__ ((constructor)); 

static
struct masterserver_plugin q3m
= { "q3m",
	q3m_plugin_version,
	masterserver_version,
	q3m_ports,
	2,
	HEARTBEAT_TIMEOUT,
	&info,
	&process,
	&free_privdata,
	&cleanup
};

static void
info(void)
{
	INFO("quake3 masterserver plugin v%s\n", q3m_plugin_version);
	INFO("  compiled for masterserver v%s\n", masterserver_version);
}

static void
free_privdata(void *data)
{
    int i;
	q3m_private_data_t *privdata = (q3m_private_data_t *) data;

	if (data == NULL) return;

    free(privdata->sv_hostname);
    free(privdata->version);
    free(privdata->mapname);
    free(privdata->gamename);
    for (i = 0; i < privdata->_players; i++)
        free(privdata->_player[i].name);
    free(privdata->_player);
	free(privdata);
}

static int
process_heartbeat(char *packet)
{
	int server_dup = 0;
	int time_diff, i;
	serverlist_t *backup_ptr;

	// first, check if server is already in our list
	for (i = 0; i < q3m.num_servers; i++) {
		if ((q3m.list[i].ip.s_addr == q3m.client.sin_addr.s_addr)
				&& (q3m.list[i].port == q3m.client.sin_port)) {
			DEBUG("duplicate server detected! (%s:%d)\n",
					inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
			server_dup = 1;
			break;
		}
	}

	INFO("heartbeat from %s:%d\n",
			inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
	// if not, then add it to the list
	if (server_dup == 0) {
		// server is not in our list so add its ip, port and a timestamp
		q3m.list[q3m.num_servers].ip = q3m.client.sin_addr;
		q3m.list[q3m.num_servers].port = q3m.client.sin_port;
		q3m.list[q3m.num_servers].lastheartbeat = time(NULL);
		DEBUG("this is server no.: %d | lastheartbeat: %d\n",
				q3m.num_servers, q3m.list[q3m.num_servers].lastheartbeat);
		// allocate memory for private data
		q3m.list[q3m.num_servers].private_data = calloc(1, sizeof(q3m_private_data_t));

		q3m.num_servers++;

		DEBUG("reallocating server list (old size: %d -> new size: %d)\n",
				q3m.num_servers * sizeof(serverlist_t),
				(q3m.num_servers+1) * sizeof(serverlist_t));

		// back up the current list pointer in case realloc() fails
		backup_ptr = q3m.list;
		q3m.list = (serverlist_t *) realloc(q3m.list, ((q3m.num_servers+1)*sizeof(serverlist_t)));
		if (q3m.list == NULL) {
			WARNING("realloc() failed trying to get %d bytes!\n",
					(q3m.num_servers+1)*sizeof(serverlist_t));
			// since the pointer is overwritten with NULL
			// we'll recover by using the backup pointer
			q3m.list = backup_ptr;
			return -2;
		} else DEBUG("reallocation successful\n");
	} else {
		time_diff = time(NULL) - q3m.list[i].lastheartbeat;
		// if time_diff is 0 the server has shutdown (most likely)
		if (time_diff == 0) {
			INFO("server %s:%u is shutting down (time_diff %d)\n",
					inet_ntoa(q3m.list[i].ip), ntohs(q3m.list[i].port),
					time_diff);
			delete_server(&q3m, i);
			server_dup = 0;
			return 2; // return "server-shutdown" code
		} else {
			// server is in already in our list so we just update the timestamp
			q3m.list[i].lastheartbeat = time(NULL);
			server_dup = 0;
		}
	}
	// server added/updated
	return 1;
}

static int
send_getstatus()
{
	int challenge, i;

	// create challenge number
	challenge = rand();
	DEBUG("challenge: %d\n", challenge);

	// prepare q3m.msg_out
	q3m.num_msgs = 1;
	q3m.msg_out_length = calloc(1, sizeof(int));
	if (q3m.msg_out_length == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", sizeof(int));
		return -2; // TODO: define retval for errors
	}
	DEBUG("allocated %d bytes for msg_out_length[]\n", sizeof(int));

	// q3m.msg_out_length[0] = q3_pkt_header_len + q3_pkt_getstatus_len;
	q3m.msg_out_length[0] = q3_pkt_header_len
			+ q3_pkt_getstatus_len + (int)(sizeof(int)*2.5);

	// allocate the memory for the outgoing packet
	q3m.msg_out = calloc(1, sizeof(char *));
	if (q3m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", sizeof(char *));
		return -2; // TODO: define retval for errors
	}

	q3m.msg_out[0] = calloc(q3m.msg_out_length[0]+1, 1);
	if (q3m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				q3m.msg_out_length[0]);
		return -2; // TODO: define retval for errors
	}
	DEBUG("allocated %d bytes for msg_out[0]\n", q3m.msg_out_length[0]+1);

	memcpy(q3m.msg_out[0], q3_pkt_header, q3_pkt_header_len);
	memcpy(q3m.msg_out[0]+q3_pkt_header_len, q3_pkt_getstatus, q3_pkt_getstatus_len);
	sprintf(q3m.msg_out[0]+q3_pkt_header_len+q3_pkt_getstatus_len, "%d", challenge);

	// write challenge into serverlist
	for (i = 0; i < q3m.num_servers; i++) {
		if ((q3m.client.sin_addr.s_addr == q3m.list[i].ip.s_addr)
				&& (q3m.client.sin_port == q3m.list[i].port)) {
			((q3m_private_data_t *) q3m.list[i].private_data)->_challenge = challenge;
			break;
		}
	}

	return 1; // send "getstatus" packet
}

static int
process_getservers(char *packet)
{
	int i, j, pkt_offset; // temp vars
	int getsrv_protocol;
	char *temp;
	q3m_private_data_t *temp_priv_data;

	INFO("getservers from %s:%u\n",
			inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));

	// we need the protocol version from the packet so we parse it
	temp = packet+q3_pkt_header_len+q3_pkt_getsrv_len+1;
	getsrv_protocol = atoi(temp);
	DEBUG("requested protocol is %d\n", getsrv_protocol);

	// got the protocol version now we can assemble the outgoing packet(s)
	DEBUG("assembling server list packet\n");

	/*
	 * packet assembler follows
	 */

	// walk the server list
	for (i = j = 0; (j < q3m.num_servers) || (q3m.num_msgs == 0); i++) {
		q3m.num_msgs++;

		// allocate memory for the packets
		q3m.msg_out = realloc(q3m.msg_out, q3m.num_msgs*sizeof(char *));
		if (q3m.msg_out == NULL) {
			ERRORV("malloc() failed to get %d bytes!\n", q3m.num_msgs*sizeof(char *));
			return -2;
		}
		q3m.msg_out_length = realloc(q3m.msg_out_length, q3m.num_msgs*sizeof(int));
		if (q3m.msg_out_length == NULL) {
			ERRORV("malloc() failed to get %d bytes!\n", q3m.num_msgs*sizeof(int));
			return -2;
		}

		// get memory for header and command
		q3m.msg_out[i] = malloc(811);
		if (q3m.msg_out[i] == NULL) {
			ERROR("malloc() failed to get 811 bytes!\n");
			return -2;
		}

		// write header and command into packet
		memcpy(q3m.msg_out[i], q3_pkt_header, q3_pkt_header_len);
		pkt_offset = q3_pkt_header_len;
		memcpy(q3m.msg_out[i]+pkt_offset, q3_pkt_getsrvrsp, q3_pkt_getsrvrsp_len);
		pkt_offset += q3_pkt_getsrvrsp_len;

		for (; (j < q3m.num_servers) && (pkt_offset < 806); j++) {
			temp_priv_data = (q3m_private_data_t *) q3m.list[j].private_data;
			// if the protocol matches, write ip/port into the packet
			if (temp_priv_data->protocol == getsrv_protocol) {
				// copy data from server list into packet
				memcpy(q3m.msg_out[i]+pkt_offset, "\\", 1);
				pkt_offset++;
				memcpy(q3m.msg_out[i]+pkt_offset, &q3m.list[j].ip, 4);
				pkt_offset += 4;
				memcpy(q3m.msg_out[i]+pkt_offset, &q3m.list[j].port, 2);
				pkt_offset += 2;
			}
		} // for j < 112

		// write footer
		memcpy(q3m.msg_out[i]+pkt_offset, q3_pkt_footer, q3_pkt_footer_len);
		pkt_offset += q3_pkt_footer_len;
		q3m.msg_out[i][pkt_offset] = '\0';
		q3m.msg_out_length[i] = pkt_offset;
		DEBUG("q3m.msg_out_length[%d] = %d\n", i, pkt_offset);
	}

	// packet with server list is ready
	return 1;
}

static int
process_statusResponse(char *packet, int packetlen)
{
	char *varname = NULL, *value = NULL;
	char *score = NULL, *ping = NULL, *name = NULL;
	int i;
	int server_dup = 0, done = 0;
	char *packetend = packet+packetlen;
	q3m_private_data_t *private_data = calloc(1, sizeof(q3m_private_data_t));
	q3m_private_data_t *oldprivdata;

	// check if source address is known
	for (i = 0; i < q3m.num_servers; i++) {
		if ((q3m.client.sin_addr.s_addr == q3m.list[i].ip.s_addr)
				&& (q3m.client.sin_port == q3m.list[i].port)) {
			server_dup = 1;
			break;
		}
	}

	// source address not known
	if (server_dup == 0) {
		WARNING("unexpected \"statusResponse\" from %s:%d ignored\n",
				inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
		return -1;
	}

	oldprivdata = (q3m_private_data_t *)q3m.list[i].private_data;

	// go to 1st "\" which is after the command string
	packet = strpbrk(packet, "\\");
	if (packet == NULL) {
		WARNING("malformed statusResponse packet received from %s:%d!\n",
			inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
		return -1;
	}

	DEBUG("begin parsing server info\n");
	while ((++packet < packetend) && !done)
	{
		// get variable name
		varname = packet;

		// go to next delimiter
		packet = strpbrk(packet, "\\");
		if (packet == NULL) {
			ERRORV("malformed statusResponse packet received from %s:%d!\n",
				inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
			return -2;
		}
		// overwrite delimiter with \0
		*packet = '\0';

		// get value
		value = ++packet;

		// go to next delimiter
		packet = strpbrk(packet, "\\\n");
		if (packet == NULL) {
			ERRORV("malformed statusResponse packet received from %s:%d!\n",
				inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
			return -2;
		}

		// check if we're at the end of the server info section
		if (*packet == '\n') done = 1;
		// overwrite delimiter with \0
		*packet = '\0';

		DEBUG("varname = \"%s\", value = \"%s\"\n", varname, value);
		// parse varname and assign the value to the struct
		if (strcmp(varname, "challenge") == 0) {
			private_data->challenge = atoi(value);
		} else if (strcmp(varname, "sv_punkbuster") == 0) {
			private_data->sv_punkbuster = atoi(value);
		} else if (strcmp(varname, "g_maxGameClients") == 0) {
			private_data->g_maxGameClients = atoi(value);
		} else if (strcmp(varname, "capturelimit") == 0) {
			private_data->capturelimit = atoi(value);
		} else if (strcmp(varname, "sv_maxclients") == 0) {
			private_data->sv_maxclients = atoi(value);
		} else if (strcmp(varname, "timelimit") == 0) {
			private_data->timelimit = atoi(value);
		} else if (strcmp(varname, "fraglimit") == 0) {
			private_data->fraglimit = atoi(value);
		} else if (strcmp(varname, "dmflags") == 0) {
			private_data->dmflags = atoi(value);
		} else if (strcmp(varname, "sv_maxPing") == 0) {
			private_data->sv_maxPing = atoi(value);
		} else if (strcmp(varname, "sv_minPing") == 0) {
			private_data->sv_minPing = atoi(value);
		} else if (strcmp(varname, "sv_hostname") == 0) {
			private_data->sv_hostname = strdup(value);
			if (private_data->sv_hostname == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				return -2;
			}
		} else if (strcmp(varname, "sv_maxRate") == 0) {
			private_data->sv_maxRate = atoi(value);
		} else if (strcmp(varname, "sv_floodProtect") == 0) {
			private_data->sv_floodProtect = atoi(value);
		} else if (strcmp(varname, "version") == 0) {
			private_data->version = strdup(value);
			if (private_data->version == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				return -2;
			}
		} else if (strcmp(varname, "g_gametype") == 0) {
			private_data->g_gametype = atoi(value);
		} else if (strcmp(varname, "protocol") == 0) {
			private_data->protocol = atoi(value);
		} else if (strcmp(varname, "mapname") == 0) {
			private_data->mapname = strdup(value);
			if (private_data->mapname == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				return -2;
			}
		} else if (strcmp(varname, "sv_privateClients") == 0) {
			private_data->sv_privateClients = atoi(value);
		} else if (strcmp(varname, "sv_allowDownload") == 0) {
			private_data->sv_allowDownload = atoi(value);
		} else if (strcmp(varname, "bot_minplayers") == 0) {
			private_data->bot_minplayers = atoi(value);
		} else if (strcmp(varname, "gamename") == 0) {
			private_data->gamename = strdup(value);
			if (private_data->gamename == NULL) {
				ERRORV("calloc() failed to get %d bytes!\n", strlen(value)+1);
				return -2;
			}
		} else if (strcmp(varname, "g_needpass") == 0) {
			private_data->g_needpass = atoi(value);
		} //else {
			// WARNING("unknown option \"%s\" in statusResponse ignored\n", varname);
		//}
	}
	DEBUG("end parsing server info\n");

	// parse player info
	private_data->_players = 0;
	while (++packet < packetend) {
		// FIXME: recover from realloc() failure
		private_data->_player = (q3m_player_data_t *) realloc(private_data->_player,
				(private_data->_players+1)*sizeof(q3m_player_data_t));
		if (private_data->_player == NULL) {
			ERRORV("realloc() failed trying to get %d bytes!\n",
					private_data->_players*sizeof(q3m_player_data_t));
			return -2;
		}

		// get player score
		score = packet;

		// go to next delimiter
		if ((packet = strpbrk(packet, " ")) == NULL) {
			ERRORV("malformed statusResponse packet received from %s:%d!\n",
				inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
			return -2;
		}
		// overwrite delimiter
		*packet = '\0';

		// parse player score
		private_data->_player[private_data->_players].score = atoi(score);

		// get player ping
		ping = ++packet;

		// go to next delimiter
		if ((packet = strpbrk(packet, " ")) == NULL) {
			ERRORV("malformed statusResponse packet received from %s:%d!\n",
				inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
			return -2;
		}
		// overwrite delimiter
		*packet = '\0';

		// parse player ping
		private_data->_player[private_data->_players].ping = atoi(ping);

		// get player name
		name = ++packet;

		// go to next delimiter
		if ((packet = strpbrk(packet, "\n")) == NULL) {
			ERRORV("malformed statusResponse packet received from %s:%d!\n",
				inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
			return -2;
		}
		// overwrite delimiter
		*packet = '\0';

		// parse player name
		private_data->_player[private_data->_players].name = strdup(name);
		if (private_data->_player[private_data->_players].name == NULL) {
			ERRORV("strdup() failed to get %d bytes!\n",
					strlen(name)+1);
			return -2;
		}

		DEBUG("player #%d name: \"%s\", ping: %d, score: %d\n",
			private_data->_players, private_data->_player[private_data->_players].name,
			private_data->_player[private_data->_players].ping,
			private_data->_player[private_data->_players].score);

		private_data->_players++;
	}

	// compare challenge to ours
	if (private_data->challenge != oldprivdata->_challenge) {
		WARNING("statusResponse challenge mismatch (%d != %d)\n",
				private_data->challenge, oldprivdata->_challenge);
		free_privdata(private_data);
		return -1;
	}

	// if we already have parsed server/player info we have to free it first
	if (q3m.list[i].private_data != NULL) free_privdata(q3m.list[i].private_data);
	q3m.list[i].private_data = private_data;

	return 0;
}

static int
process_getmotd(char *packet, int packetlen)
{
	char *version, *renderer, *challenge;
	char *varname = NULL, *value = NULL;
	char *packetend = packet+packetlen;

	packet += q3_pkt_header_len+q3_pkt_getmotd_len+2;

	while ((++packet < packetend) && (*packet != '\x0a')) {
		// save position as variable name
		varname = packet;

		// go to next delimiter
		packet = strpbrk(packet, "\\");
		if (packet == NULL) {
			WARNING("invalid \"getmotd\" from %s:%d received; ignored\n",
					inet_ntoa(q3m.client.sin_addr),
					ntohs(q3m.client.sin_port));
			return -1;
		}

		// overwrite delimiter with \0
		*packet = '\0';

		// save next position as value
		value = ++packet;

		// go to next delimiter
		packet = strpbrk(packet, "\\\"");
		if (packet == NULL) {
			WARNING("invalid \"getmotd\" from %s:%d received; ignored\n",
					inet_ntoa(q3m.client.sin_addr),
					ntohs(q3m.client.sin_port));
			return -1;
		}

		// overwrite delimiter with \0
		*packet = '\0';

		// parse
		if (strcmp(varname, "version") == 0) {
			version = strdup(value);
			if (version == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				return -2;
			}
		} else if (strcmp(varname, "renderer") == 0) {
			renderer = strdup(value);
			if (renderer == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				return -2;
			}
		} else if (strcmp(varname, "challenge") == 0) {
			challenge = strdup(value);
			if (challenge == NULL) {
				ERRORV("strdup() failed to get %d bytes!\n", strlen(value)+1);
				return -2;
			}
		} else {
			WARNING("unknown variable \"%s\" in \"getmotd\" packet ignored\n",
					varname);
		}
	}

	INFO("getmotd from %s:%d running \"%s\" with a \"%s\"\n",
			inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port),
			version, renderer);

	// we got all we need to assemble the motd packet
	q3m.msg_out = calloc(1, sizeof(char *));
	if (q3m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(char *));
		return -2;
	}
	q3m.msg_out_length = calloc(1, sizeof(int));
	if (q3m.msg_out_length == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				sizeof(int));
		return -2;
	}
	q3m.msg_out_length[0] = q3_pkt_header_len+q3_pkt_motd_len
							+ strlen(Q3M_MOTD)
							+ (int)(sizeof(int)*2.5);
	q3m.msg_out[0] = calloc(q3m.msg_out_length[0]+1, 1);
	if (q3m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				q3m.msg_out_length[0]);
		return -2;
	}
	q3m.num_msgs = 1;
	sprintf(q3m.msg_out[0], q3_pkt_motd, atoi(challenge), Q3M_MOTD);

	// clean up
	free(version);
	free(renderer);
	free(challenge);

	return 1;
}

static int
process(char *packet, int packetlen)
{
	int retval;

	// check if packet is q3a related
	if (strncmp(packet, q3_pkt_header, q3_pkt_header_len) == 0) {
		DEBUG("Q3A protocol marker detected!\n");
		// which packet did we receive?
		if (strcmp(packet+q3_pkt_header_len, q3_pkt_heartbeat) == 0) {
			retval = process_heartbeat(packet);
			if (retval == 1) {
				send_getstatus();
				return 1; // "send packet" code
			}
			return retval;
		} else if (strncmp(packet+q3_pkt_header_len, q3_pkt_getsrv, q3_pkt_getsrv_len) == 0) {
			return process_getservers(packet);
		} else if (strncmp(packet+q3_pkt_header_len, q3_pkt_statusrsp, q3_pkt_statusrsp_len) == 0) {
			return process_statusResponse(packet, packetlen);
		} else if (strncmp(packet+q3_pkt_header_len, q3_pkt_getmotd, q3_pkt_getmotd_len) == 0) {
			return process_getmotd(packet, packetlen);
		}
		WARNING("unknown packet received!\n");
		return -1;
	} // end if for 0xff 0xff 0xff 0xff marker
	WARNING("invalid packet received: Q3A protocol marker missing!\n");
	return -1; // invalid packet
}

static void
cleanup(void)
{
	int i;

	if (q3m.num_servers > 0) {
		for (i = 0; i < q3m.num_servers; i++) {
			free_privdata(q3m.list[i].private_data);
		}
	}
}

void
init_plugin(void)
{
	register_plugin(&q3m);
}

