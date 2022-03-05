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
 * The author can be contacted at andre@malchen.de
 */

#include "../masterserver.h"

// for future use
// #define Q3M_PROTOCOL IPPROTO_UDP

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
const char	q3_pkt_delimiter[]	= "\\";
const char	q3_pkt_delimiter2[] = " ";
const char	q3_pkt_delimiter3[]	= "\n";

const char q3m_plugin_version[] = "0.7.2";
static int q3m_ports[] = { 27950, 27951 };

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
	// TODO: what about custom cvars (Administrator, ...) ?
} q3m_private_data_t;

static void info(void); // print information about plugin
static int process(char *packet); // process packet and return a value
static int process_heartbeat(char *packet);
static int process_getservers(char *packet);
static int send_getstatus();
static int process_statusResponse(char *packet);
static void cleanup(void);
void _init(void);

static
struct masterserver_plugin q3m
= { "q3m",
	q3m_plugin_version,
	masterserver_version,
	q3m_ports,
	2,
//	Q3M_PROTOCOL, // for future use
	HEARTBEAT_TIMEOUT,
	&info,
	&process,
	&cleanup
};

static void
info(void)
{
	INFO("quake3 masterserver plugin v%s\n", q3m_plugin_version);
	INFO("  compiled for masterserver v%s\n", masterserver_version);
}

static int
process_heartbeat(char *packet)
{
	int server_dup = 0;
	int time_diff, i;

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
		q3m.list[q3m.num_servers].ip = q3m.client.sin_addr;
		DEBUG("client address added\n");
		q3m.list[q3m.num_servers].port = q3m.client.sin_port;
		DEBUG("client port added\n");
		q3m.list[q3m.num_servers].lastheartbeat = time(NULL);
		DEBUG("client heartbeat timestamp added\n");
		DEBUG("this is server no.: %d | lastheartbeat: %d\n",
				q3m.num_servers, q3m.list[q3m.num_servers].lastheartbeat);
		// allocate memory for private data
		q3m.list[q3m.num_servers].private_data = calloc(1, sizeof(q3m_private_data_t));

		q3m.num_servers++;

		DEBUG("reallocating server list (old size: %d -> new size: %d)\n",
				q3m.num_servers * sizeof(serverlist_t),
				(q3m.num_servers+1) * sizeof(serverlist_t));

		q3m.list = (serverlist_t *) realloc(q3m.list, ((q3m.num_servers+1)*sizeof(serverlist_t)));
		if (q3m.list == NULL) {
			//WARNING("can't increase q3m.list size; out of memory!\n");
			ERRORV("realloc() failed trying to get %d bytes!\n",
					(q3m.num_servers+1)*sizeof(serverlist_t));
			// since the pointer is overwritten with NULL
			// we can't recover; so just exit here
			// XXX: maybe save the old pointer somewhere so
			//		we can continue?
			// FIXME: don't pthread_exit() here instead return -3 or so
			pthread_exit((void *) -1);
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

	// create challenge
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
			+ q3_pkt_getstatus_len + (int)(sizeof(int)*2.5)+1;

	// allocate the memory for the outgoing packet
	q3m.msg_out = calloc(1, sizeof(char *));
	if (q3m.msg_out == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", sizeof(char *));
		return -2; // TODO: define retval for errors
	}

	DEBUG("calloc(%d, %d) total: %d\n", q3m.msg_out_length[0], sizeof(char),
			q3m.msg_out_length[0]+sizeof(char));
	q3m.msg_out[0] = calloc(q3m.msg_out_length[0], sizeof(char));
	if (q3m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				q3m.msg_out_length[0]*sizeof(char));
		return -2; // TODO: define retval for errors
	}
	DEBUG("allocated %d bytes for msg_out[0]\n", q3m.msg_out_length[0]);

	memcpy(q3m.msg_out[0], q3_pkt_header, q3_pkt_header_len);
	memcpy(q3m.msg_out[0]+q3_pkt_header_len, q3_pkt_getstatus, q3_pkt_getstatus_len);
	// FIXME: write challenge into packet
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
	int i, pkt_offset, pkt_servers = 0; // temp vars
	int getsrv_protocol;
	char *temp_start, *temp_end, *temp_string;
	q3m_private_data_t *temp_priv_data;

	INFO("getservers from %s:%u\n",
			inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));

	// we need the protocol version from the packet so we parse it
	temp_start = packet+q3_pkt_header_len+q3_pkt_getsrv_len;
	temp_end = strpbrk(temp_start+1, q3_pkt_delimiter2);
	if (temp_end == NULL)
		temp_end = packet+strlen(packet);
	temp_string = (char *) malloc((temp_end-temp_start)*sizeof(char));
	if (temp_string == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n",
			(temp_end-temp_start)*sizeof(char));
		return -2;
	}
	strncpy(temp_string, temp_start+1, (temp_end-temp_start)-1);
	temp_string[(temp_end-temp_start)-1] = '\0';
	getsrv_protocol = atoi(temp_string);
	free(temp_string);

	// got the protocol version now we can assemble the outgoing packet(s)
	DEBUG("assembling server list packet\n");

	/*
	 * This is the new, badly documented packet assembler.
	 */
	q3m.msg_out = malloc(sizeof(char *));
	if (q3m.msg_out == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n", sizeof(char *));
		return -2;
	}

	q3m.msg_out_length = malloc(sizeof(int));
	if (q3m.msg_out_length == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n", sizeof(int));
		return -2;
	}

	// get memory for header and command
	q3m.msg_out[q3m.num_msgs] = malloc((q3_pkt_header_len+q3_pkt_getsrvrsp_len)*sizeof(char));
	if (q3m.msg_out[q3m.num_msgs] == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n",
				(q3_pkt_header_len+q3_pkt_getsrvrsp_len)*sizeof(char));
		return -2;
	}

	// write header and command into packet
	memcpy(q3m.msg_out[q3m.num_msgs], q3_pkt_header, q3_pkt_header_len);
	pkt_offset = q3_pkt_header_len;
	memcpy(q3m.msg_out[q3m.num_msgs]+pkt_offset, q3_pkt_getsrvrsp, q3_pkt_getsrvrsp_len);
	pkt_offset += q3_pkt_getsrvrsp_len;

	// walk the server list
	for (i = 0; i < q3m.num_servers; i++) {
		temp_priv_data = (q3m_private_data_t *) q3m.list[i].private_data;
		// if the protocol matches, write ip/port into the packet
		if (temp_priv_data->protocol == getsrv_protocol) {
			// check if we need to create a new packet
			if (pkt_servers == 112) {
				DEBUG("pkt_offset: %d\n", pkt_offset);
				// packet is full so mark the end with footer and null terminate
				q3m.msg_out[q3m.num_msgs] = realloc(q3m.msg_out[q3m.num_msgs],
						(pkt_offset+q3_pkt_footer_len+1)*sizeof(char));
				if (q3m.msg_out[q3m.num_msgs] == NULL) {
					ERRORV("realloc() failed trying to get %d bytes!\n",
							(pkt_offset+q3_pkt_footer_len+1)*sizeof(char *));
					return -2;
				}
				memcpy(q3m.msg_out[q3m.num_msgs]+pkt_offset, q3_pkt_footer, q3_pkt_footer_len);
				pkt_offset += q3_pkt_footer_len;
				q3m.msg_out[q3m.num_msgs][pkt_offset] = '\0';
				DEBUG("pkt_offset: %d\n", pkt_offset);
				q3m.msg_out_length[q3m.num_msgs] = pkt_offset;
				DEBUG("q3m.msg_out_length[%d] = %d\n", q3m.num_msgs, pkt_offset);

				// and allocate memory for next packet
				q3m.num_msgs++;
				q3m.msg_out = realloc(q3m.msg_out, (q3m.num_msgs+1)*sizeof(char *));
				if (q3m.msg_out == NULL) {
					ERRORV("realloc() failed trying to get %d bytes!\n",
							(q3m.num_msgs+1)*sizeof(char *));
					return -2;
				}

				q3m.msg_out_length = realloc(q3m.msg_out_length, (q3m.num_msgs+1)*sizeof(int));
				if (q3m.msg_out_length == NULL) {
					ERRORV("realloc() failed trying to get %d bytes!\n",
							(q3m.num_msgs+1)*sizeof(int));
					return -2;
				}

				// get memory for the next server
				DEBUG("q3m.num_msgs: %d\n", q3m.num_msgs);
				q3m.msg_out[q3m.num_msgs] = malloc((q3_pkt_header_len+q3_pkt_getsrvrsp_len)*sizeof(char));
				if (q3m.msg_out[q3m.num_msgs] == NULL) {
					ERRORV("malloc() failed trying to get %d bytes!\n",
							(q3_pkt_header_len+q3_pkt_getsrvrsp_len)*sizeof(char));
					return -2;
				}

				// add header and command to packet
				memcpy(q3m.msg_out[q3m.num_msgs], q3_pkt_header, q3_pkt_header_len);
				pkt_offset = q3_pkt_header_len;
				memcpy(q3m.msg_out[q3m.num_msgs]+pkt_offset, q3_pkt_getsrvrsp, q3_pkt_getsrvrsp_len);
				pkt_offset += q3_pkt_getsrvrsp_len;

				// reset the server counter
				pkt_servers = 0;
			}

			q3m.msg_out[q3m.num_msgs] = realloc(q3m.msg_out[q3m.num_msgs],
					(pkt_offset+7)*sizeof(char));
			if (q3m.msg_out[q3m.num_msgs] == NULL) {
				ERRORV("realloc() failed trying to get %d bytes!\n",
						(pkt_offset+7)*sizeof(char));
				return -2;
			}

			// copy data from server list into packet
			memcpy(q3m.msg_out[q3m.num_msgs]+pkt_offset, q3_pkt_delimiter, 1);
			pkt_offset++;
			memcpy(q3m.msg_out[q3m.num_msgs]+pkt_offset, &q3m.list[i].ip, 4);
			pkt_offset += 4;
			memcpy(q3m.msg_out[q3m.num_msgs]+pkt_offset, &q3m.list[i].port, 2);
			pkt_offset += 2;
			pkt_servers++;
		}
	}

	DEBUG("pkt_offset: %d\n", pkt_offset);
	// packet is full so mark the end with footer and null terminate
	q3m.msg_out[q3m.num_msgs] = realloc(q3m.msg_out[q3m.num_msgs],
			(pkt_offset+q3_pkt_footer_len+1)*sizeof(char));
	if (q3m.msg_out[q3m.num_msgs] == NULL) {
		ERRORV("realloc() failed trying to get %d bytes!\n",
				(pkt_offset+q3_pkt_footer_len+1)*sizeof(char));
		return -2;
	}
	memcpy(q3m.msg_out[q3m.num_msgs]+pkt_offset, q3_pkt_footer, q3_pkt_footer_len);
	pkt_offset += q3_pkt_footer_len;
	q3m.msg_out[q3m.num_msgs][pkt_offset] = '\0';
	DEBUG("pkt_offset: %d\n", pkt_offset);
	q3m.msg_out_length[q3m.num_msgs] = pkt_offset;
	DEBUG("q3m.msg_out_length[%d] = %d\n", q3m.num_msgs, pkt_offset);

	q3m.num_msgs++;

	// packet with server list is ready
	return 1;
}

static int
process_statusResponse(char *packet)
{
	char *temp_start = NULL, *temp_end = NULL, *temp_end2 = NULL;
	char *temp_pkt = NULL, *temp_plr = NULL;
	char *temp_varname = NULL, *temp_value = NULL;
	char *temp_string = NULL;
	int temp_offset, temp_size, i, serv_num;
	int server_dup = 0;
	q3m_private_data_t *private_data = calloc(1, sizeof(q3m_private_data_t));
	q3m_private_data_t *temp;

	// check if source address is known
	for (i = 0; i < q3m.num_servers; i++) {
		if ((q3m.client.sin_addr.s_addr == q3m.list[i].ip.s_addr)
				&& (q3m.client.sin_port == q3m.list[i].port)) {
			server_dup = 1;
			serv_num = i;
			break;
		}
	}

	// source address not known
	if (server_dup == 0) {
		WARNING("unexpected \"statusResponse\" from %s:%d ignored\n",
				inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
		return -1;
	}

	temp = (q3m_private_data_t *) q3m.list[serv_num].private_data;

	// parse server/player info and isolate server info
	// the 1st "\n" is after the command
	temp_start = strpbrk(packet, "\n");
	temp_offset = temp_start - packet;
	// the 2nd "\n" marks the end of the server info
	// this also marks the beginning of player info
	temp_end = strpbrk(packet+temp_offset+1, "\n");
	temp_size = temp_end - temp_start;
	temp_pkt = (char *) malloc(temp_size*sizeof(char));
	if (temp_pkt == NULL) {
		ERRORV("malloc() failed trying to get %d bytes!\n",
				temp_size*sizeof(char));
		return -2;
	}
	// isolate/copy the server info into temp_pkt
	strncpy(temp_pkt, packet+temp_offset+1, temp_size-1);
	temp_pkt[temp_size-1] = '\0';
	temp_end2 = temp_pkt+temp_size-1;
	// begin parsing the server info
	DEBUG("begin parsing server info\n");
	DEBUG("%p < %p => %d\n", temp_start+1, temp_end2, (temp_start+1<temp_end2));
	for (	temp_start = strpbrk(temp_pkt, "\\");
			temp_start+1 < temp_end2;
			temp_start = temp_end)
	{
		temp_end = strpbrk(temp_start+1, "\\");
		// calculate # of chars
		temp_size = temp_end - temp_start;
		// allocate memory
		temp_varname = (char *) malloc(temp_size*sizeof(char));
		if (temp_varname == NULL) {
			ERRORV("malloc() failed trying to get %d bytes!\n",
					temp_size*sizeof(char));
			return -2;
		}
		// copy it into a temporary buffer
		strncpy(temp_varname, temp_start+1, temp_size-1);
		// don't forget \0
		temp_varname[temp_size-1] = '\0';

		// previous end posiion is now start position
		temp_start = temp_end;
		// get position of next delimiter
		temp_end = strpbrk(temp_end+1, "\\");
		// check if we're at the end of the varname/value pairs
		if (temp_end == NULL)
			temp_end = &temp_pkt[strlen(temp_pkt)];
		// calculate # of chars
		temp_size = temp_end - temp_start;
		// allocate memory
		temp_value = (char *) malloc(temp_size*sizeof(char));
		if (temp_value == NULL) {
			ERRORV("malloc() failed trying to get %d bytes!\n",
					temp_size*sizeof(char));
			return -2;
		}
		// copy chars into temporary buffer
		strncpy(temp_value, temp_start+1, temp_size-1);
		// don't forget \0
		temp_value[temp_size-1] = '\0';

		// parse varname and assign the value to the struct
		if (strcmp(temp_varname, "challenge") == 0) {
			private_data->challenge = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "sv_punkbuster") == 0) {
			private_data->sv_punkbuster = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "g_maxGameClients") == 0) {
			private_data->g_maxGameClients = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "capturelimit") == 0) {
			private_data->capturelimit = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "sv_maxclients") == 0) {
			private_data->sv_maxclients = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "timelimit") == 0) {
			private_data->timelimit = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "fraglimit") == 0) {
			private_data->fraglimit = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "dmflags") == 0) {
			private_data->dmflags = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "sv_maxPing") == 0) {
			private_data->sv_maxPing = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "sv_minPing") == 0) {
			private_data->sv_minPing = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "sv_hostname") == 0) {
			private_data->sv_hostname = temp_value;
		} else if (strcmp(temp_varname, "sv_maxRate") == 0) {
			private_data->sv_maxRate = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "sv_floodProtect") == 0) {
			private_data->sv_floodProtect = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "version") == 0) {
			private_data->version = temp_value;
		} else if (strcmp(temp_varname, "g_gametype") == 0) {
			private_data->g_gametype = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "protocol") == 0) {
			private_data->protocol = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "mapname") == 0) {
			private_data->mapname = temp_value;
		} else if (strcmp(temp_varname, "sv_privateClients") == 0) {
			private_data->sv_privateClients = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "sv_allowDownload") == 0) {
			private_data->sv_allowDownload = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "bot_minplayers") == 0) {
			private_data->bot_minplayers = atoi(temp_value);
			free(temp_value);
		} else if (strcmp(temp_varname, "gamename") == 0) {
			private_data->gamename = temp_value;
		} else if (strcmp(temp_varname, "g_needpass") == 0) {
			private_data->g_needpass = atoi(temp_value);
			free(temp_value);
		} else {
			// WARNING("unknown option \"%s\" in statusResponse ignored\n", temp_varname);
			free(temp_value);
		}
		// free the temporary buffer
		free(temp_varname);
	}
	free(temp_pkt);
	DEBUG("end parsing server info\n");

	// parse player info
	private_data->_players = 0;
	temp_start = strpbrk(packet+q3_pkt_header_len+q3_pkt_statusrsp_len, "\n");
	do { 
		temp_offset = temp_start - packet;
		temp_end = strpbrk(packet+temp_offset+1, "\n");
		// if temp_end is NULL there are no players on the server and thus
		// no info to parse
		if (temp_end == NULL) break;
		private_data->_players++;
		private_data->_player = (q3m_player_data_t *) realloc(private_data->_player,
				private_data->_players*sizeof(q3m_player_data_t));
		if (private_data->_player == NULL) {
			ERRORV("realloc() failed trying to get %d bytes!\n",
					private_data->_players*sizeof(q3m_player_data_t));
			return -2;
		}
		temp_size = temp_end - temp_start;

		// get the whole string
		temp_string = (char *) malloc(temp_size*sizeof(char));
		if (temp_string == NULL) {
			ERRORV("malloc() failed trying to get %d bytes!\n",
					temp_size*sizeof(char));
			return -2;
		}
		strncpy(temp_string, packet+temp_offset+1, temp_size-1);
		temp_string[temp_size-1] = '\0';

		// parse player score
		temp_end = strpbrk(temp_string, " ");
		temp_plr = (char *) malloc(temp_end-temp_string+1);
		if (temp_plr == NULL) {
			ERRORV("malloc() failed trying to get %d bytes!\n",
					temp_end-temp_string+1);
			return -2;
		}
		strncpy(temp_plr, temp_string, temp_end - temp_string);
		temp_plr[temp_end-temp_string] = '\0';
		private_data->_player[private_data->_players-1].score = atoi(temp_plr);
		free(temp_plr);

		// parse player ping
		temp_start = temp_end;
		temp_end = strpbrk(temp_start+1, " ");
		temp_plr = (char *) malloc(temp_end-temp_start);
		if (temp_plr == NULL) {
			ERRORV("malloc() failed trying to get %d bytes!\n",
					temp_end-temp_start);
			return -2;
		}
		strncpy(temp_plr, temp_start+1, temp_end - temp_start - 1);
		temp_plr[temp_end-temp_start-1] = '\0';
		private_data->_player[private_data->_players-1].ping = atoi(temp_plr);
		free(temp_plr);

		// parse player name
		temp_start = temp_end+1;
		temp_end = strpbrk(temp_start+1, "\"");
		private_data->_player[private_data->_players-1].name = (char *) malloc(temp_end-temp_start);
		if (private_data->_player[private_data->_players-1].name == NULL) {
			ERRORV("malloc() failed trying to get %d bytes!\n",
					temp_end-temp_start);
			return -2;
		}
		strncpy(private_data->_player[private_data->_players-1].name,
				temp_start+1, temp_end-temp_start-1);
		private_data->_player[private_data->_players-1].name[temp_end-temp_start-1] = '\0';

		free(temp_string);
	} while ((temp_start = strpbrk(packet+temp_offset+1, "\n")));

	// compare challenge to ours
	if (private_data->challenge != temp->_challenge) {
		WARNING("statusResponse challenge mismatch (%d != %d)\n",
				private_data->challenge, temp->_challenge);
		free(private_data->sv_hostname);
		free(private_data->version);
		free(private_data->mapname);
		free(private_data->gamename);
		for (i = 0; i < private_data->_players; i++)
			free(private_data->_player[i].name);
		free(private_data->_player);
		free(private_data);
		return -1;
	}

	// if we already have parsed server/player info we have to free it first
	if (q3m.list[i].private_data != NULL) {
		free(temp->sv_hostname);
		free(temp->version);
		free(temp->mapname);
		free(temp->gamename);
		for (i = 0; i < temp->_players; i++)
			free(temp->_player[i].name);
		free(temp->_player);
		free(temp);
	}
	q3m.list[serv_num].private_data = private_data;

	return 0;
}

static int
process_getmotd(char *packet)
{
	char *version, *renderer, *challenge;
	char *temp_start, *temp_end, *temp_varname, *temp_value;
	int temp_size;

	temp_start = packet+q3_pkt_header_len+q3_pkt_getmotd_len+2;
	temp_end = strpbrk(temp_start+1, "\\");
	if (temp_end == NULL) {
		WARNING("invalid \"getmotd\" from %s:%d received; ignored\n",
				inet_ntoa(q3m.client.sin_addr),
				ntohs(q3m.client.sin_port));
		return -1;
	}
	do {
		temp_size = temp_end - temp_start;
		temp_varname = (char *) malloc(temp_size*sizeof(char));
		if (temp_varname == NULL) {
			ERRORV("malloc() failed trying to get %d bytes!\n",
					temp_size*sizeof(char));
			return -2;
		}
		strncpy(temp_varname, temp_start+1, temp_size-1);
		temp_varname[temp_size-1] = '\0';

		temp_start = temp_end;
		temp_end = strpbrk(temp_start+1, "\\");
		if (temp_end == NULL)
			temp_end = packet+strlen(packet)-2;
		temp_size = temp_end - temp_start;
		temp_value = (char *) malloc(temp_size*sizeof(char));
		if (temp_value == NULL) {
			ERRORV("malloc() failed trying to get %d bytes!\n",
					temp_size*sizeof(char));
			return -2;
		}
		strncpy(temp_value, temp_start+1, temp_size-1);
		temp_value[temp_size-1] = '\0';

		if (strcmp(temp_varname, "version") == 0) {
			version = temp_value;
		} else if (strcmp(temp_varname, "renderer") == 0) {
			renderer = temp_value;
		} else if (strcmp(temp_varname, "challenge") == 0) {
			challenge = temp_value;
		} else {
			WARNING("unknown variable \"%s\" in \"getmotd\" packet ignored\n",
					temp_varname);
			free(temp_value);
		}
		free(temp_varname);
		temp_start = temp_end;
	} while((temp_end = strpbrk(temp_start+1, "\\")));

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
	q3m.msg_out_length[0] = q3_pkt_header_len+q3_pkt_motd_len+strlen(Q3M_MOTD)+10+1;
	q3m.msg_out[0] = calloc(q3m.msg_out_length[0], sizeof(char));
	if (q3m.msg_out[0] == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n",
				q3m.msg_out_length[0]*sizeof(char));
		return -2;
	}
	q3m.num_msgs = 1;
	sprintf(q3m.msg_out[0], q3_pkt_motd, atoi(challenge), Q3M_MOTD);

	free(version);
	free(renderer);
	free(challenge);
	return 1;
}

static int
process(char *packet)
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
			return process_statusResponse(packet);
		} else if (strncmp(packet+q3_pkt_header_len, q3_pkt_getmotd, q3_pkt_getmotd_len) == 0) {
			return process_getmotd(packet);
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
	int i, j;
	q3m_private_data_t *tmp_privdata;

	if (q3m.num_servers > 0) {
		for (i = 0; i < q3m.num_servers; i++) {
			tmp_privdata = (q3m_private_data_t *) q3m.list[i].private_data;
			for (j = 0; j < tmp_privdata->_players; j++)
				free(tmp_privdata->_player[j].name);
			free(tmp_privdata->_player);
			free(tmp_privdata->version);
			free(tmp_privdata->mapname);
			free(tmp_privdata->gamename);
			free(tmp_privdata->sv_hostname);
			free(tmp_privdata);
			free(q3m.list[i].private_data);
		}
	}
}

void
_init(void)
{
	register_plugin(&q3m);
}

