#ifndef _MASTERSERVER_H
#define _MASTERSERVER_H

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <math.h>

#include "logging.h"

#ifndef MASTERSERVER_LIB_DIR
#define MASTERSERVER_LIB_DIR "/usr/lib/lasange/masterserver"
#endif

int debug = 0; // global debug var
char masterserver_version[] = "0.3.1";

typedef struct {
	struct in_addr ip; // ip adress
	in_port_t port; // port
	int lastheartbeat; // timestamp
	void *private_data; // data specific to plugin
} serverlist_t;

typedef char plugin_name[32];

// struct for plugins
// TODO: multi port support
struct masterserver_plugin {
	// the following has to be filled by the plugin
	plugin_name name; // plugin name
	const char *pversion; // plugin version
	const char *cversion; // which masterserver version was this compiled against
	unsigned int *port; // port(s) to listen on
	int num_ports;
	// following is for future use
	//const int protocol;	// which protocol to use? tcp, udp, ...
	int heartbeat_timeout; // after how many seconds does a server timeout and is then kicked out of the serverlist

	void (*info) (void); // show info about plugin
	int (*process) (char *packet); // process a packet
	void (*cleanup) (void); // free private data
	// end plugin fill section

	struct masterserver_plugin *next; // next plugin in linked list
	pthread_mutex_t mutex; // mutex for this struct
	unsigned int num_servers; // current number of servers in list
	serverlist_t *list;	 // pointer to serverlist
	char **msg_out; // array of packets to send to client
	int *msg_out_length; // lengths of outgoing packets
	int num_msgs; // how many packets are in msg_out array
	unsigned int enabled; // plugin enabled?
	int *socket_d; // socket(s)
	int num_sockets;
	struct sockaddr_in client; // client strcture
	struct sockaddr_in *server; // server struct
	pthread_t thread_nr; // thread id
	pthread_t heartbeat_thread_nr; // heartbeat thread id
};

// plugins call the following function
extern void register_plugin(struct masterserver_plugin *me);
// generic function for deleting servers in plugin server list
extern void delete_server(struct masterserver_plugin *me, int server_num);

#endif // _MASTERSERVER_H

