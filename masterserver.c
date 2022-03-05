/* This file is part of masterserver.
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
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <net/if.h>
#include <pwd.h>
#include <grp.h>

#include <pthread.h>
#include <dlfcn.h>

#include "masterserver.h" // masterserver stuff

#define MAX_MSG_LENGTH	1024 // max packet length

// linked list for keeping track of plugins
// beware! it's a pointer array! :)
struct masterserver_plugin *plugins = NULL;


// function prototypes
void exit_printhelp(void); // print help ans exit
void exit_printversion(void); // print version and exit
void plugin_thread(void *arg); // main thread calling plugin routines
void plugin_heartbeat_thread(void *arg); // remove dead servers from server list


void
exit_printhelp(void)
{
	fprintf(stdout,
"Usage: masterserver [options]\n"
"Options:\n"
"  --no-daemon	-D	Don't go into daemon mode.\n"
"  --debug	-d	debug mode\n"
"  --help	-h	output this help text\n"
"  --listen-on	-i	bind the masterserver to specific interfaces\n"
"  --log-file	-l	log stdout to a file\n"
"  --version	-v	display version information and exit\n"
//"  -f			Specify different location of the configuration file.\n"
//"				Default: /etc/masterserver.conf\n\n"
"Report bugs to <andre@malchen.de>.\n");

	exit(0);
}

void
exit_printversion(void)
{
	fprintf(stdout,
"Copyright (C) 2002 André Schulz and Ingo Rohlfs\n"
"masterserver comes with NO WARRANTY,\n"
"to the extent permitted by law.\n"
"You may redistribute copies of masterserver\n"
"under the terms of the GNU General Public License.\n"
"For more information about these matters,\n"
"see the files named COPYING.\n\n");

	exit(0);
}

void
register_plugin(struct masterserver_plugin *me)
{
	struct masterserver_plugin **i;
	if (strcmp(me->cversion, MASTERSERVER_VERSION) != 0) {
		fprintf(stdout, "masterserver Error: plugin %s was compiled for masterserver version %s (this is %s)\n", me->name, me->cversion, MASTERSERVER_VERSION);
		fprintf(stdout, "masterserver Error: plugin %s disabled\n", me->name);
		me->enabled = 0;
	}

	// append to linked list
	// thanks to the iptables team from whom I've borrowed this piece of code
	for (i = &plugins; *i; i = &(*i)->next);
	me->next = NULL;
	*i = me;

	// fill plugin structure
	me->nr_servers = 0;
	me->list = calloc((me->nr_servers + 1), sizeof(serverlist_t)); // initialize server list
	me->msg_out = NULL;
	me->msg_out_length = 0;
	me->enabled = 1; // plugin is enabled
	me->info(); // display plugin info
}

int
main(int argc, char *argv[])
{
	// cmdline options
	int option_logfile = 0;
	int option_bind_to_interface = 0;
	int option_no_daemon = 0;

	void *handle[10]; // for dlopen() calls, max. 10 plugins
	int retval;	// return value of syscalls
	unsigned int i, num_plugins, num_plugins_enabled, num_listen_interfaces = 0;
	DIR *plugin_dir; // for opening the plugin dir
	struct dirent *plugin_dir_entry; 
	char path[sizeof(MASTERSERVER_LIB_DIR) + 256]; // path to plugin dir
	char *logfile; // pointer to argv argument
	char **listen_interface; // ptr array for storing interface/device names
	struct masterserver_plugin **j; // temporary variable

	// temporary variables
	int setsockopt_temp = 1;
	uid_t uid_temp;
	pid_t temp_pid;
	struct passwd *passwd_temp;

	fprintf(stdout, "masterserver v%s\n", MASTERSERVER_VERSION);

	// TODO: read config

	listen_interface = calloc(num_listen_interfaces+1, sizeof(char *));
	// cmdline parser
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--debug") == 0 || strcmp(argv[i], "-d") == 0) debug = 1;
		else if (strcmp(argv[i], "--log-file") == 0 || strcmp(argv[i], "-l") == 0) {
			option_logfile = 1;
			logfile = argv[i+1];
			i = i + 2;
		} else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
			exit_printhelp();
		} else if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-v") == 0) {
			exit_printversion();
		} else if (strcmp(argv[i], "--listen-on") == 0 || strcmp(argv[i], "-i") == 0) {
			uid_temp = getuid();
			if (uid_temp != 0) {
				fprintf(stderr, "masterserver Error: you have to be root to bind to specific interfaces\n");
				fprintf(stderr, "masterserver: exiting ...\n");
				return -1;
			}
			do {
				i++;
				if (strlen(argv[i]) > IFNAMSIZ) {
					fprintf(stderr, "%s Error on line %d: interface/device name on cmdline is longer than IFNAMSIZ(%d)\n", __FILE__, __LINE__, IFNAMSIZ);
					fprintf(stderr, "masterserver: exiting ...\n");
					return -1;
				}
				listen_interface[num_listen_interfaces] = argv[i];
				// well the interface/device names have to be null terminated ...
				listen_interface[num_listen_interfaces] = strcat(listen_interface[num_listen_interfaces], ""); 
				num_listen_interfaces++;
				listen_interface = realloc(listen_interface, (num_listen_interfaces + 1) * sizeof(char *));
				// limit to 15 interfaces
				if (i + 1 >= argc || num_listen_interfaces >= 15) break;
			} while (strncmp(argv[i+1], "-", 1) != 0);
			option_bind_to_interface = 1;
		} else if (strcmp(argv[i], "--no-daemon") == 0 || strcmp(argv[i], "-D") == 0) {
			option_no_daemon = 1;
		} else {
			fprintf(stdout, "unknown option: %s\n", argv[i]);
			return -1;
		}
	}

	// check -D --no-daemon cmdline argument
	if (option_no_daemon == 0) {
		fprintf(stdout, "masterserver: becoming a daemon ... bye, bye\n");
		if ( (temp_pid = fork()) < 0) {
			fprintf(stderr, "%s Error on line %d: fork (errno: %d - %s)\n", __FILE__, __LINE__, errno, strerror(errno));
			fprintf(stderr, "masterserver: exiting ...\n");
			return -1;
		} else if (temp_pid != 0) {
			exit(0);
		}

		retval = setsid();
		if (retval == -1) {
			fprintf(stderr, "%s Error on line %d: setsid (errno: %d - %s)\n", __FILE__, __LINE__, errno, strerror(errno));
			fprintf(stderr, "masterserver: exiting ...\n");
			exit(-1);
		}

		retval = chdir("/");
		if (retval == -1) {
			fprintf(stderr, "%s Error on line %d: chdir (errno: %d - %s)\n", __FILE__, __LINE__, errno, strerror(errno));
			fprintf(stderr, "masterserver: exiting ...\n");
			exit(1);
		}

		umask(0);

		if (option_logfile == 0) {
			if (freopen("/dev/null", "a", stdout) != stdout) {
				fprintf(stderr, "masterserver Error: freopen (errno: %d - %s)\n", errno, strerror(errno));
				fprintf(stderr, "masterserver: exiting ...\n");
				return -1;
			}
		}
	}

	// check -l --log-file cmdline argument
	if (option_logfile == 1) {
		fprintf(stdout, "masterserver: logging stdout to %s\n", logfile);
		if (freopen(logfile, "a", stdout) != stdout) {
			fprintf(stderr, "%s Error on line %d: freopen (errno: %d - %s)\n", __FILE__, __LINE__, errno, strerror(errno));
			fprintf(stderr, "masterserver: exiting ...\n");
			return -1;
		}
		// change buffering to per line so we actually see something in the logfile
		setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
	}

	// open directory MASTERSERVER_LIB_DIR
	if (debug == 1) fprintf(stdout, "masterserver Debug: opening %s\n", MASTERSERVER_LIB_DIR);
	plugin_dir = opendir(MASTERSERVER_LIB_DIR);
	if (plugin_dir == NULL) {
		fprintf(stderr, "%s Error on line %d: opendir(%s) (errno: %d - %s)\n", __FILE__, __LINE__, MASTERSERVER_LIB_DIR, errno, strerror(errno));
		fprintf(stderr, "masterserver: exiting ...\n");
		return -1;
	}

	num_plugins = 0;
	// load all libs in MASTERSERVER_LIB_DIR
	while ((plugin_dir_entry = readdir(plugin_dir))) {
		// omit . and .. and files
		// FIXME: don't try to load files != .so
		if (	strcmp(plugin_dir_entry->d_name, ".") == 0
				|| strcmp(plugin_dir_entry->d_name, "..") == 0)
			continue;
		else
		{
			sprintf(path, "%s/%s", MASTERSERVER_LIB_DIR, plugin_dir_entry->d_name);
			if (debug == 1) fprintf(stdout, "masterserver Debug: path: %s\n", path);
			handle[num_plugins] = dlopen(path, RTLD_NOW);
			if (!handle[num_plugins]) {
				fprintf(stderr, "%s Error on line %d: dlopen (%s)\n", __FILE__, __LINE__, dlerror());
				fprintf(stderr, "masterserver: exiting ...\n");
				return -1;
			}
			if (debug == 1) fprintf(stdout, "masterserver Debug: dlopen() successful\n");
			fprintf(stdout, "masterserver: dynamic library %s loaded\n", plugin_dir_entry->d_name);
			num_plugins++;
		}
	}
	retval = closedir(plugin_dir);
	if (retval == -1) {
		fprintf(stderr, "%s Error on line %d: closedir (retval: %d - errno: %d - %s)\n", __FILE__, __LINE__, retval, errno, strerror(errno));
		fprintf(stderr, "masterserver: exiting ...\n");
		return -1;
	}
	if (debug == 1) fprintf(stdout, "masterserver Debug: closedir succeeded\n");

	// print out a summary
	fprintf(stdout, "masterserver: %d plugins loaded\n", num_plugins);

	// create sockets and bind them
	// had to be done because threads inherit the original user
	// and we don't want the threads to be root
	// TODO: sanity checks (e.g. duplicate ports)
	j = &plugins;
	for (i = 0; i < num_plugins; i++) {
		if (*j == NULL) break;
		if ((*j)->enabled == 0) continue;
	
		// create socket for plugin
		(*j)->socket_d = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (debug == 1) fprintf(stdout, "masterserver Debug: plugin nr %d %s | socket_d is %d\n", i, (*j)->name, (*j)->socket_d);

		// receive broadcast packets
		if (debug == 1) fprintf(stdout, "masterserver Debug: sizeof(setsockopt_temp) is %d\n", sizeof(setsockopt_temp));
		retval = setsockopt((*j)->socket_d, SOL_SOCKET, SO_BROADCAST, &setsockopt_temp, sizeof(setsockopt_temp));
		if (retval == -1) {
			fprintf(stderr, "%s Error on line %d: setsockopt (retval: %d - errno: %d - %s)\n", __FILE__, __LINE__, retval, errno, strerror(errno));
			return -1;
		}

		// bind socket to the interfaces specified in -i --listen-on
		if (option_bind_to_interface == 1) {
			fprintf(stdout, "masterserver: binding socket to %d interfaces/devices ...\n", num_listen_interfaces);
			for (i = 0; i < num_listen_interfaces; i++) {
				retval = setsockopt((*j)->socket_d, SOL_SOCKET, SO_BINDTODEVICE, listen_interface[i], sizeof(listen_interface[i]));
				if (retval == -1) {
					fprintf(stderr, "%s Error on line %d: setsockopt (retval: %d - errno: %d - %s)\n", __FILE__, __LINE__, retval, errno, strerror(errno));
					fprintf(stderr, "masterserver: exiting ...\n");
					return -1;
				}
				fprintf(stdout, "masterserver: %s socket successfully bound to %s\n", (*j)->name, listen_interface[i]);
			}
		}

		// fill sockaddr_in structure
		(*j)->server.sin_family = AF_INET;
		(*j)->server.sin_port = htons((*j)->port); // port number from plugin
		(*j)->server.sin_addr.s_addr = htonl(INADDR_ANY);

		// bind socket to structure
		retval = bind((*j)->socket_d, (struct sockaddr *) &(*j)->server, sizeof((*j)->server));
		if (retval == -1) {
			fprintf(stderr, "%s Error on line %d: bind (retval: %d - errno: %d - %s)\n", __FILE__, __LINE__, retval, errno, strerror(errno));
			return -1;
		}
	}
	fprintf(stdout, "masterserver: sockets successfully created and bound\n");

	if (option_bind_to_interface == 1) {
		if (debug == 1) fprintf(stdout, "masterserver Debug: getting uid of user \"masterserver\"\n");
		// check if user "masterserver" exists
		// and get user infos
		passwd_temp = getpwnam("masterserver");
		if (passwd_temp == NULL) {
			fprintf(stderr, "%s Error on line %d: getpwnam (errno: %d - %s)\n", __FILE__, __LINE__, errno, strerror(errno));
			fprintf(stderr, "masterserver: exiting ...\n");
			return -1;
		}

		// change uid/gid to "masterserver" to drop privileges
		if (debug == 1) fprintf(stdout, "masterserver Debug: setting gid to %d\n", passwd_temp->pw_gid);
		// change group to the one of user "masterserver"
		retval = setgid(passwd_temp->pw_gid);
		if (retval == -1) {
			fprintf(stderr, "%s Error on line %d: setgid (retval: %d - errno: %d - %s)\n", __FILE__, __LINE__, retval, errno, strerror(errno));
			fprintf(stderr, "masterserver: exiting ...\n");
			return -1;
		}

		if (debug == 1) fprintf(stdout, "masterserver Debug: setting uid to %d (\"masterserver\")\n", passwd_temp->pw_uid);
		// change uid to "masterserver"
		retval = setuid(passwd_temp->pw_uid);
		if (retval == -1) {
			fprintf(stderr, "%s Error on line %d: setuid (retval: %d - errno: %d - %s)\n", __FILE__, __LINE__, retval, errno, strerror(errno));
			fprintf(stderr, "masterserver: exiting ...\n");
			return -1;
		}
		fprintf(stdout, "masterserver: give up root permissions/uid/gid change successful\n");
	}

	// main part
	if (debug == 1) fprintf(stdout, "masterserver Debug: creating plugin threads...\n");
	j = &plugins;
	for (i = 0; i < num_plugins; i++) {
		if (*j == NULL) break;
		if ((*j)->enabled == 0) continue;

		// create plugin thread
		retval = pthread_create(&(*j)->thread_nr, NULL, (void *) plugin_thread, (void *) *j);
		if (retval != 0) {
			switch(retval) {
				case EAGAIN:
					fprintf(stderr, "%s Error on line %d: pthread_create returned an error; not enough system resources to create a process for the new thread\n", __FILE__, __LINE__);
					fprintf(stderr, "                     or more than %d threads are already active\n", PTHREAD_THREADS_MAX);
					fprintf(stderr, "exiting...\n");
	                return -1;
    	    }
		}
		fprintf(stdout, "masterserver: created %s plugin thread\n", (*j)->name);
		j = &(*j)->next; // point j to next plugin in linked list
	}

	// create heartbeat threads
	if (debug == 1) fprintf(stdout, "masterserver Debug: creating heartbeat threads...\n");
	j = &plugins;
	for (i = 0; i < num_plugins; i++) {
		if (*j == NULL) break;
		if ((*j)->enabled == 0) continue;

		retval = pthread_create(&(*j)->heartbeat_thread_nr, NULL, (void *) plugin_heartbeat_thread, (void *) *j);
		if (retval != 0) {
			switch(retval) {
				case EAGAIN:
					fprintf(stderr, "\nError: pthread_create returned an error; not enough system resources to create a process for the new thread\n");
					fprintf(stderr, "       or more than %d threads are already active\n", PTHREAD_THREADS_MAX);
					fprintf(stderr, "exiting...\n");
	                return -1;
			}
		}
		fprintf(stdout, "masterserver: created heartbeat thread for %s.\n", (*j)->name);
		j = &(*j)->next;
	}

	// cleanup and exit
	// (not really anyway; this is just to stop the parent from eating cpu time)
	fprintf(stdout, "masterserver: joining plugin threads for graceful cleanup/shutdown... \n");
	for (j = &plugins; *j; j = &(*j)->next) {
		if (debug == 1) fprintf(stdout, "masterserver Debug: joining thread #%ld\n", (*j)->thread_nr);
		retval = pthread_join((*j)->thread_nr, NULL);
		if (retval != 0) {
			fprintf(stderr, "%s Error on line %d: pthread_join\n", __FILE__, __LINE__);
			return -1;
		}
		if (debug == 1) fprintf(stdout, "masterserver Debug: thread #%ld exited; cleaning up...\n", (*j)->thread_nr);
		free((*j)->list);
		close((*j)->socket_d);
		if (debug == 1) fprintf(stdout, "masterserver Debug: thread #%ld clean up successful\n", (*j)->thread_nr);
	}

	if (debug == 1) fprintf(stdout, "masterserver Debug: closing dynamic libs ...\n");
	for (; num_plugins > 0; num_plugins--) dlclose(&handle[num_plugins]);
	if (debug == 1) fprintf(stdout, "masterserver Debug: dynamic libs successfully closed\n");

	return 0;
}

void
plugin_thread(void *arg)
{
	int retval; // temp var for return values
	char *msg_in = calloc(MAX_MSG_LENGTH, sizeof(char)); // buffer for incoming packet
	struct masterserver_plugin *me = (struct masterserver_plugin *) arg;
	int client_len;
	client_len = sizeof(me->client);

	fprintf(stdout, "%s_thread: hello world\n", me->name);

	// main loop
	while (1) {
		retval = recvfrom(me->socket_d, msg_in, MAX_MSG_LENGTH, 0, (struct sockaddr *) &me->client, &client_len);
		if (retval == -1) {
			fprintf(stderr, "%s Error on line %d: recvfrom (retval: %d - errno: %d - %s)\n", __FILE__, __LINE__, retval, errno, strerror(errno));
			fprintf(stderr, "%s_thread Debug: socket_d is %d\n", me->name, me->socket_d);
			fprintf(stderr, "%s_thread Debug: MAX_MSG_LENGTH is %d\n", me->name, MAX_MSG_LENGTH);
			fprintf(stderr, "exiting...\n");
			pthread_exit((void *) 1);
		}
		if (debug == 1) fprintf(stdout, "%s_thread Debug: %d bytes received\n", me->name, retval);

		if (debug == 1) fprintf(stdout, "%s_thread Debug: locking mutex\n", me->name);
		retval = pthread_mutex_lock(&me->mutex);
		if (retval != 0) {
			fprintf(stderr, "%s_thread %s Error on line %d: pthread_mutex_lock (retval: %d)\n", me->name, __FILE__, __LINE__, retval);
			pthread_exit((void *) -1);
		}
		if (debug == 1) fprintf(stdout, "%s_thread Debug: mutex succesfully locked\n", me->name);

		retval = me->process(msg_in);
		if (retval == -2) {
			fprintf(stderr, "%s_thread Error: plugin reported: not enough memory for an outgoing packet\n", me->name);
		} else if (retval == -1) {
			fprintf(stdout, "%s_thread: plugin reported: invalid packet received\n", me->name);
		} else if (retval == 0) {
			fprintf(stdout, "%s_thread: plugin reported: server successfully added\n", me->name);
		} else if (retval == 1) {
			if (debug == 1) {
				fprintf(stdout, "%s_thread Debug: me->process retval is %d\n", me->name, retval);
				fprintf(stdout, "%s_thread Debug: me->socket_d is %d\n", me->name, me->socket_d);
				fprintf(stdout, "%s_thread Debug: me->msg_out_length is %d\n", me->name, me->msg_out_length);
			}
			fprintf(stdout, "%s_thread debug: sending server list to %s:%u\n", me->name, inet_ntoa(me->client.sin_addr), ntohs(me->client.sin_port));

			retval = sendto(me->socket_d, me->msg_out, me->msg_out_length, 0, (struct sockaddr *) &me->client, client_len);
			if (retval == -1) {
				fprintf(stderr, "%s Error on line %d: sendto (retval: %d - errno: %d - %s)\n", __FILE__, __LINE__, retval, errno, strerror(errno));
			}
			if (debug == 1) fprintf(stdout, "%s_thread Debug: %d bytes sent\n", me->name, retval);
		} else if (retval == 2) {
			fprintf(stdout, "%s_thread: plugin reported: server deleted\n", me->name);
		}

		if (me->msg_out != NULL) {
			if (debug == 1) fprintf(stdout, "%s_thread Debug: freeing me->msg_out\n", me->name);
			free(me->msg_out);
			me->msg_out = NULL;
		}

		if (debug == 1) fprintf(stdout, "%s_thread Debug: unlocking mutex\n", me->name);
		retval = pthread_mutex_unlock(&me->mutex);
		if (retval != 0) {
			fprintf(stderr, "%s Error on line %d: pthread_mutex_unlock\n", __FILE__, __LINE__);
			pthread_exit((void *) -1);
		}
	} // end while(1)
}

void
plugin_heartbeat_thread(void *arg)
{
	struct masterserver_plugin *me = (struct masterserver_plugin *) arg;
	int i = 0;
	int heartbeat_diff = 0;
	int retval; // temp var for return values

	fprintf(stdout, "%s_heartbeat_thread: hello world\n", me->name);

	// main loop
	while (1) {
		if (debug == 1) fprintf(stdout, "%s_heartbeat_thread Debug: sleeping %d seconds ...\n", me->name, me->heartbeat_timeout);
		sleep(me->heartbeat_timeout);
		if (debug == 1) fprintf(stdout, "%s_heartbeat_thread Debug: waking up\n", me->name);

		if (debug == 1) fprintf(stdout, "%s_heartbeat_thread Debug: locking mutex\n", me->name);
		retval = pthread_mutex_lock(&me->mutex);
		if (retval != 0) {
			fprintf(stderr, "%s Error on line %d: pthread_mutex_lock\n", __FILE__, __LINE__);
			pthread_exit((void *) -1);
		}

		for (i = 0; i < me->nr_servers; i++) {
			heartbeat_diff = time(NULL) - me->list[i].lastheartbeat;
			if (heartbeat_diff > 300) {
				fprintf(stdout, "%s_heartbeat_thread: server %d died (heartbeat_diff %d); deleting from list\n", me->name, i, heartbeat_diff);
				delete_server(me, i);
			} else {
				if (debug == 1) fprintf(stdout, "%s_heartbeat_thread Debug: server %d is alive (heartbeat_diff %d)\n", me->name, i, heartbeat_diff);
			}
		}

		if (debug == 1) fprintf(stdout, "%s_heartbeat_thread Debug: unlocking mutex\n", me->name);
		retval = pthread_mutex_unlock(&me->mutex);
		if (retval != 0) {
			fprintf(stderr, "%s Error on line %d: pthread_mutex_unlock\n", __FILE__, __LINE__);
			pthread_exit((void *) -1);
		}
	} // end while(1)
}

void
delete_server(struct masterserver_plugin *me, int server_num)
{
	int i = server_num;
	for (; i < me->nr_servers; i++) {
		me->list[i].ip = me->list[i+1].ip;
		me->list[i].port = me->list[i+1].port;
		me->list[i].lastheartbeat = me->list[i+1].lastheartbeat;
	}
	me->nr_servers--;
	if (debug == 1) fprintf(stdout, "%s: reallocating server list (old size: %d -> new size: %d)\n", me->name, (me->nr_servers + 2) * sizeof(serverlist_t), (me->nr_servers + 1) * sizeof(serverlist_t));
	me->list = (serverlist_t *) realloc(me->list, (me->nr_servers + 1) * sizeof(serverlist_t));
	if (debug == 1) fprintf(stdout, "%s: reallocation successful\n", me->name);
}

