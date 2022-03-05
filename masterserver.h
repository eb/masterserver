#ifndef _MASTERSERVER_H
#define _MASTERSERVER_H

#include "logging.h"

#ifndef MASTERSERVER_LIB_DIR
#define MASTERSERVER_LIB_DIR "/usr/lib/lasange/masterserver"
#endif

int debug = 0; // global debug var
int master_shutdown = 0; // to signal graceful shutdown (by sigint handler)
char masterserver_version[] = "0.4";

// XXX: merge struct in_addr and in_port_t to struct sockaddr_in ?
typedef struct {
	struct in_addr ip; // ip adress
	in_port_t port; // port
	int lastheartbeat; // timestamp
	void *private_data; // data specific to plugin
} serverlist_t;

typedef struct {
	int protocol;
	in_port_t num;
} port_t;

// struct for plugins
struct masterserver_plugin {
	// the following has to be filled by the plugin
	const char name[32]; // plugin name
	const char *pversion; // plugin version
	const char *cversion; // which masterserver version was this compiled against
	port_t *port; // port(s) to listen on
	int num_ports;
	int heartbeat_timeout; // server heartbeat timeout in seconds

	void (*info) (void); // show info about plugin
	int (*process) (char *, int); // process a packet
	void (*free_privdata) (void *);	// free private data
	void (*cleanup) (void);	// free private data
	// end plugin fill section

	struct masterserver_plugin *next; // next plugin in linked list
	pthread_mutex_t mutex; // mutex for this struct
	unsigned int num_servers; // current number of servers in list
	serverlist_t *list; // pointer to serverlist
	char **msg_out; // array of packets to send to client
	int *msg_out_length; // lengths of outgoing packets
	int num_msgs; // how many packets are in msg_out array
	unsigned int enabled; // plugin enabled?
	int *socket_d; // socket(s)
	int num_sockets;
	struct sockaddr_in client; // client struct
	struct sockaddr_in *server; // server struct
	pthread_t thread_nr; // thread id
	pthread_t heartbeat_thread_nr; // heartbeat thread id
};

// plugins call the following function
extern void register_plugin(struct masterserver_plugin *);
// generic function for deleting servers in plugin server list
extern void delete_server(struct masterserver_plugin *, int);

#endif // _MASTERSERVER_H

