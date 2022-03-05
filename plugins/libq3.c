#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "../masterserver.h"

#define Q3M_PORT 27950
#define Q3M_PLUGIN_VERSION "0.55"
#define HEARTBEAT_TIMEOUT 30
#define Q3_HEADER "\xff\xff\xff\xff"

static void info(void); // print information about plugin
static int process(char*); // process packet and return a value


static
struct masterserver_plugin q3m
= { NULL,
	"q3m",
	Q3M_PLUGIN_VERSION,
	MASTERSERVER_VERSION,
	Q3M_PORT,
	HEARTBEAT_TIMEOUT,
	PTHREAD_MUTEX_INITIALIZER,
	&info,
	&process
};

static void
info(void)
{
	fprintf(stdout,
"quake3 masterserver plugin v%s\n"
"  compiled for masterserver v%s\n", Q3M_PLUGIN_VERSION, MASTERSERVER_VERSION);
}

static int
process(char *packet)
{
	int i, server_dup, time_diff; // temp vars
	unsigned char *ip, *port; // temp vars for creating outgoing packets
	char *msg_out = NULL; // pointer to outgoing packet
	int msg_out_offset; // temp var for keeping track of where were writing the outgoing packet
	int msg_out_length; // length of outgoing packet

	// check if packet is q3a related
	if (strncmp(packet, Q3_HEADER, 4) == 0) {
		if (debug == 1) fprintf(stdout, "libq3 Debug: Q3A protocol marker detected!\n");
		if (strncmp(packet+4, "heartbeat", 9) == 0) {
			// first, check if server is already in our list
			for (i = 0; i < q3m.nr_servers; i++) {
				if (debug == 1) {
					fprintf(stdout, "libq3 Debug: list[%d].ip is %s | list[%d].port is %d\n", i, inet_ntoa(q3m.list[i].ip), i, ntohs(q3m.list[i].port));
					fprintf(stdout, "libq3 Debug: client.sin_addr is %s | client.sin_port is %d\n", inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
				}
				if ((q3m.list[i].ip.s_addr == q3m.client.sin_addr.s_addr) && (q3m.list[i].port == q3m.client.sin_port)) {
					if (debug == 1) fprintf(stdout, "libq3 Debug: duplicate server detected! (%s:%d)\n", inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
					server_dup = 1;
					break;
				}
			}
			if (server_dup != 1) {
				// if not, then add it to the list
				q3m.list[q3m.nr_servers].ip = q3m.client.sin_addr;
				if (debug == 1) fprintf(stdout, "libq3 Debug: client address added\n");
				q3m.list[q3m.nr_servers].port = q3m.client.sin_port;
				if (debug == 1) fprintf(stdout, "libq3 Debug: client port added\n");
				q3m.list[q3m.nr_servers].lastheartbeat = time(NULL);
				if (debug == 1) fprintf(stdout, "libq3 Debug: client heartbeat timestamp added\n");
				fprintf(stdout, "libq3: Heartbeat from %s:%u; added to server list\n", inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
				if (debug == 1) fprintf(stdout, "libq3 Debug: this is server no.: %d | lastheartbeat: %d\n", q3m.nr_servers, q3m.list[q3m.nr_servers].lastheartbeat);
				q3m.nr_servers++;

				if (debug == 1) fprintf(stdout, "libq3 Debug: reallocating server list (old size: %d -> new size: %d)\n", q3m.nr_servers * sizeof(serverlist_t), (q3m.nr_servers+1) * sizeof(serverlist_t));
				if (q3m.nr_servers > 0)
					q3m.list = (serverlist_t *) realloc(q3m.list, ((q3m.nr_servers + 1) * sizeof(serverlist_t)));
				if (q3m.list == NULL) fprintf(stderr, "libq3 Warning: can't increase %s.list size; out of memory!\n", q3m.name);
				if (debug == 1) fprintf(stdout, "libq3 Debug: reallocation successful\n");
			} else {
				time_diff = time(NULL) - q3m.list[i].lastheartbeat;
				// if time_diff is 0 the server has shutdown (most likely)
				if (time_diff == 0) {
					fprintf(stdout, "libq3: server %d (%s:%u) is shutting down. bye, bye. (time_diff %d)\n", i, inet_ntoa(q3m.list[i].ip), ntohs(q3m.list[i].port), time_diff);
					delete_server(&q3m, i);
					server_dup = 0;
					return 2;
				} else {
					// server is in already in our list so we just update the timestamp
					fprintf(stdout, "libq3: heartbeat from %s:%d; already in server list; updating heartbeat timestamp (time_diff %d)\n", inet_ntoa(q3m.list[i].ip), ntohs(q3m.list[i].port), time_diff);
					q3m.list[i].lastheartbeat = time(NULL);
					server_dup = 0;
				}
			}
			return 0; // server added to list
		} else if (strncmp(packet+4, "getservers", 10) == 0) {
			if (debug == 1) {
				fprintf(stdout, "libq3 Debug: getservers from %s:%u\n", inet_ntoa(q3m.client.sin_addr), ntohs(q3m.client.sin_port));
				fprintf(stdout, "libq3 Debug: assembling server list packet\n");
			}

			/*
			 * the following char array will be our outgoing packet.
			 * first, we'll calculate the length.
			 * the length consists of the following values:
			 * - length of header - strlen(Q3_HEADER)
			 * - number of servers in our list (incl. separator "\") - q3m.nr_servers * (sizeof(q3m.list[0].ip) + sizeof(q3m.list[0].port))
			 * - end of packet "\EOT"
			 */

			msg_out_length = strlen(Q3_HEADER) + strlen("getserversResponse") + strlen("\\EOT") + (q3m.nr_servers * (sizeof(q3m.list[0].ip) + sizeof(q3m.list[0].port) + 1));
			if (debug == 1) {
				fprintf(stdout, "libq3 Debug: %d + %d + %d + (%d * (%d + %d + 1)) = %d\n", strlen(Q3_HEADER), strlen("getserversResponse"), strlen("\\EOT"), q3m.nr_servers, sizeof(q3m.list[0].ip), sizeof(q3m.list[0].port), msg_out_length);
				fprintf(stdout, "libq3 Debug: msg_out_length is %d\n", msg_out_length);
			}

			// allocate the memory for the char array
			msg_out = (char *) calloc(msg_out_length, sizeof(char));
			if (msg_out == NULL) {
				fprintf(stderr, "libq3 Error: couldn't allocate memory for sending out udp message!\n");
				fprintf(stderr, "libq3 Error: exiting...\n");
				return -2; // TODO: define retval for errors
			}

			// copy Q3_HEADER into the char array
			sprintf(msg_out, "%s", Q3_HEADER);
			sprintf(msg_out+strlen(Q3_HEADER), "%s", "getserversResponse");
			msg_out_offset = strlen(Q3_HEADER) + strlen("getserversResponse");

			// create the UDP packet
			for (i = 0; i < q3m.nr_servers; i++) {
				if (debug == 1) fprintf(stdout, "libq3 Debug: msg_out_offset is %d\n", msg_out_offset);

				// put ip and port in char arrays
				ip = (unsigned char *) &q3m.list[i].ip;
				port = (unsigned char *) &q3m.list[i].port;

				// append ip and port to msg_out
				sprintf(msg_out+msg_out_offset, "\\%c%c%c%c%c%c", ip[0], ip[1], ip[2], ip[3], port[0], port[1]);
				if (debug == 1) {
					fprintf(stdout, "libq3 Debug: server+port addr in hex: %x %x %x %x %x %x\n", ip[0], ip[1], ip[2], ip[3], port[0], port[1]);
					fprintf(stdout, "libq3 Debug: processed server no.: %d | ip %s | port %u\n", i, inet_ntoa(q3m.list[i].ip), ntohs(q3m.list[i].port));
				}

				msg_out_offset = msg_out_offset + 7;
			}

			// append end of packet "\EOT"
			sprintf(msg_out+msg_out_offset, "\\EOT");

			q3m.msg_out = msg_out;
			q3m.msg_out_length = msg_out_length;

			// return status 1
			// packet with server list is ready
			return 1;
		}
	} // end if for 0xff 0xff 0xff 0xff marker
	return -1; // invalid packet
}

void
_init(void)
{
	register_plugin(&q3m);
}

