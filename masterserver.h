#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#define MASTERSERVER_VERSION "0.2"

#ifndef MASTERSERVER_LIB_DIR
#define MASTERSERVER_LIB_DIR "/usr/lib/lasange/masterserver"
#endif

int debug = 0; // global debug var

typedef char plugin_name[32];

typedef struct {
	struct in_addr ip; // ip adress
	in_port_t port; // port
	int lastheartbeat; // timestamp
} serverlist_t;

// struct for plugins
struct masterserver_plugin {
	struct masterserver_plugin *next; // next plugin in linked list

	plugin_name name; // plugin name
	const char *pversion; // plugin version
	const char *cversion; // which masterserver version was this compiled against
	const unsigned int port; // port to listen to
	int heartbeat_timeout; // after how many seconds does a server timeout and is then kciked out fo the serverlist

	pthread_mutex_t mutex; // mutex for this strcture

	void (*info)(void); // show info about plugin
	int (*process)(char *packet); // process a packet

	serverlist_t *list;	 // pointer to serverlist
	char *msg_out; // pointer to preprocessed serverlist to send out to client
	int msg_out_length; // length of outgoing packet
	unsigned int nr_servers; // current number of servers in list
	unsigned int enabled; // plugin enabled?
	int socket_d; // socket nr
	struct sockaddr_in server, client; // server and client strcture
	pthread_t thread_nr; // thread id
	pthread_t heartbeat_thread_nr; // heartbeat thread id
};

// plugins call the following function
extern void register_plugin(struct masterserver_plugin *me);
// generic function for deleting servers in plugin server list
extern void delete_server(struct masterserver_plugin *me, int);

