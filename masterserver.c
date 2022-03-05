/* masterserver.c: A generic masterserver for various games. */
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

#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdarg.h>

#include <dirent.h> // opendir()
#include <sys/socket.h> // for socket() etc.
#include <net/if.h> // IFNAMSIZ
#include <pwd.h> // for changing user
#include <grp.h> // for changing user
#include <dlfcn.h> // for dlopen() etc.
#include <sys/select.h> // for select()

#include "masterserver.h" // masterserver stuff

#define MAX_PKT_LEN	1024 // max packet length

#undef LOG_SUBNAME
#define LOG_SUBNAME "main" // logging subcategory description

// linked list for keeping track of plugins
// beware! it's a pointer array! :)
struct masterserver_plugin *plugins = NULL;


// function prototypes
extern void delete_server(struct masterserver_plugin *me, int server_num); // generic function for removing servers from server list
void exit_printhelp(void); // print help and exit
void exit_printversion(void); // print version and exit
void give_up_root_privileges(void); // self explanatory
int load_plugins(char *masterserver_plugin_dir, void *handle[]); // load plugins from the given directory
void plugin_thread(void *arg); // main thread calling plugin routines
void plugin_heartbeat_thread(void *arg); // remove dead servers from server list
extern void register_plugin(struct masterserver_plugin *me); // plugins call this functions to register themselves

void
exit_printhelp(void)
{
	fprintf(stdout,
"Usage: masterserver [options]\n"
"Options:\n"
"  -D\tgo into daemon mode\n"
"  -d\tdebug mode\n"
"  -h\toutput this help text\n"
"  -i\tbind the masterserver to specific interfaces\n"
"    \t(use more than once for multiple interfaces)\n"
"  -l\tlog stdout to a file\n"
/*"  -L\tset log level\n"
"    \t0 = INFO\n"
"    \t1 = WARNING\n"
"    \t2 = ERROR\n"*/
"  -p\tset location of plugins\n"
"  -V\tdisplay version information and exit\n"
"Report bugs to <andre@malchen.de>.\n");
}

void
exit_printversion(void)
{
	fprintf(stdout,
"Copyright (C) 2003 André Schulz and Ingo Rohlfs\n"
"masterserver comes with NO WARRANTY,\n"
"to the extent permitted by law.\n"
"You may redistribute copies of masterserver\n"
"under the terms of the GNU General Public License.\n"
"For more information about these matters,\n"
"see the files named COPYING.\n\n");

	exit(0);
}

void
give_up_root_privileges(void)
{
	int retval = 0;
	struct passwd *passwd_temp;

	DEBUG("getting uid of user \"masterserver\"\n");
	// check if user "masterserver" exists
	// and get user infos
	passwd_temp = getpwnam("masterserver");
	if (passwd_temp == NULL) {
		ERRORV("getpwnam() (errno: %d - %s)\n", errno, strerror(errno));
		exit(-1);
	}

	// change uid/gid to "masterserver" to drop privileges
	DEBUG("setting gid to %d\n", passwd_temp->pw_gid);
	// change group to the one of user "masterserver"
	retval = setgid(passwd_temp->pw_gid);
	if (retval == -1) {
		ERRORV("setgid() (errno: %d - %s)\n", errno, strerror(errno));
		exit(-1);
	}

	DEBUG("setting uid to %d (\"masterserver\")\n", passwd_temp->pw_uid);
	// change uid to "masterserver"
	retval = setuid(passwd_temp->pw_uid);
	if (retval == -1) {
		ERRORV("setuid() (errno: %d - %s)\n", errno, strerror(errno));
		exit(-1);
	}
	INFO("give up root permissions and uid/gid change successful\n");
}

int
load_plugins(char *masterserver_plugin_dir, void *handle[])
{
	int retval = 0;
	int num_plugins = 0;
	DIR *plugin_dir; // for opening the plugin dir
	struct dirent *plugin_dir_entry; 
	char path[PATH_MAX]; // path to plugin dir

	// open plugin directory
	DEBUG("opening %s\n", masterserver_plugin_dir);
	plugin_dir = opendir(masterserver_plugin_dir);
	if (plugin_dir == NULL) {
		ERRORV("opendir(%s) (errno: %d - %s)\n", masterserver_plugin_dir, errno, strerror(errno));
		return -1;
	}

	while ((plugin_dir_entry = readdir(plugin_dir))) {
		// omit . and ..
		// FIXME: don't try to load files != .so
		if ((strcmp(plugin_dir_entry->d_name, ".") == 0)
				|| (strcmp(plugin_dir_entry->d_name, "..") == 0))
			continue;
		else
		{
			snprintf(path,
				strlen(masterserver_plugin_dir)+plugin_dir_entry->d_reclen+2,
				"%s/%s", masterserver_plugin_dir, plugin_dir_entry->d_name);
			DEBUG("snprintf wrote %d chars\n",
				strlen(masterserver_plugin_dir)+plugin_dir_entry->d_reclen+2);
			DEBUG("path: %s\n", path);
			handle[num_plugins] = dlopen(path, RTLD_NOW);
			if (!handle[num_plugins])
			{
				ERRORV("dlopen (%s)\n", dlerror());
				exit(-1);
			}
			DEBUG("dlopen() successful\n");
			INFO("%s loaded\n", plugin_dir_entry->d_name);
			num_plugins++;
		}
	}

	retval = closedir(plugin_dir);
	if (retval == -1)
	{
		ERRORV("closedir(%s) (errno: %d - %s)\n", plugin_dir, errno, strerror(errno));
		return -1;
	}
	DEBUG("closedir succeeded\n");

	return num_plugins;
}

extern void
register_plugin(struct masterserver_plugin *me)
{
	struct masterserver_plugin **i;

	if (strcmp(me->cversion, masterserver_version) != 0) {
		WARNING("plugin %s was compiled for masterserver version %s (this is %s)\n", me->name, me->cversion, masterserver_version);
		WARNING("plugin %s disabled\n", me->name);
		me->enabled = 0;
	} else {
		me->enabled = 1; // plugin is enabled
	}

	// append to linked list
	for (i = &plugins; *i; i = &(*i)->next);
	me->next = NULL;
	*i = me;

	// initialize plugin structure
	// me->mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_init(&me->mutex, NULL);
	me->num_servers = 0;
	me->list = calloc(1, sizeof(serverlist_t)); // initialize server list
	if (me->list == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", sizeof(serverlist_t));
		exit(-1);
	}
	me->num_sockets = 0;
	me->socket_d = NULL;
	me->server = calloc(me->num_ports, sizeof(struct sockaddr_in));
	if (me->server == NULL) {
		ERRORV("calloc() failed trying to get %d bytes!\n", me->num_ports*sizeof(struct sockaddr_in));
		exit(-1);
	}
	me->msg_out = NULL;
	me->msg_out_length = NULL;
	me->info(); // display plugin info
}

int
main(int argc, char *argv[])
{
	// cmdline options
	int option_logfile = 0;
	int option_bind_to_interface = 0;
	int option_daemon = 0;
	int option_plugin_dir = 0;
	int i, k, l, num_plugins;

	void *handle[10]; // for dlopen() calls, max. 10 plugins
	int retval;	// return value of syscalls
	unsigned int num_plugins_enabled, num_listen_interfaces = 0;
	char *logfile; // pointer to argv argument
	char *masterserver_plugin_dir; // pointer to argv argument
	char **listen_interface = NULL; // ptr array for storing interface/device names
	struct masterserver_plugin **j; // temporary variable

	// temporary variables
	int setsockopt_temp = 1;
	uid_t uid_temp;
	pid_t temp_pid;

	// seed the rng; needed for challenge creation in q3 plugin
	srand(time(NULL));

	log_init(NULL, "masterserver");
	INFO("masterserver v%s\n", masterserver_version);

	// TODO: read config

	// cmdline parser
	while (1) {
		//retval = getopt(argc, argv, "?dDhi:l:L:p:V");
		retval = getopt(argc, argv, "?dDhi:l:p:V");
		if (retval == -1) break;

		switch (retval) {
			case 'd':
				debug = 1;
				break;
			case 'l':
				option_logfile = 1;
				logfile = argv[optind-1];
				break;
			/*case 'L':
				_log_level = atoi(argv[optind-1]);
				if ((_log_level < 0) || (_log_level > 2)) {
					ERROR("log level must be 0 <= x <= 2\n");
					return -1;
				}
				break;*/
			case 'V':
				exit_printversion();
			case 'i':
				uid_temp = getuid();
				/*if (uid_temp != 0) {
					fprintf(stderr, "masterserver Error: you have to be root to bind to specific interfaces\n");
					return -1;
				}*/
				if (strlen(argv[optind-1]) > IFNAMSIZ) {
					ERRORV("interface/device name is longer than IFNAMSIZ = %d"
							" chars\n", IFNAMSIZ);
					return -1;
				}

				num_listen_interfaces++;
				listen_interface = realloc(listen_interface, num_listen_interfaces*sizeof(char *));
				listen_interface[num_listen_interfaces-1] = argv[optind-1];
				option_bind_to_interface = 1;
				break;
			case 'D':
				option_daemon = 1;
				break;
			case 'p':
				masterserver_plugin_dir = argv[optind-1];
				option_plugin_dir = 1;
				break;
			case 'h':
			case '?':
			default:
				exit_printhelp();
				return -1;
		} // switch(retval)
	} // while(1)
	// XXX: this is a hack to get multi port working
	if (num_listen_interfaces == 0 && !option_bind_to_interface) num_listen_interfaces = 1;

	// check -l cmdline argument
	if (option_logfile) {
		INFO("masterserver: logging stdout to %s\n", logfile);

		// initialize log file
		retval = log_init(logfile, "masterserver");
		if (retval == -1) {
			ERROR("log_init()\n");
			return -1;
		}

		// log stdout to log file
		/*if (freopen(logfile, "a", stdout) != stdout) {
			ERRORV("freopen() (errno: %d - %s)\n", errno, strerror(errno));
			return -1;
		}*/

		// change buffering to per line so we actually see something in the logfile
		setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
	}

	// check -D cmdline argument
	if (option_daemon) {
		INFO("masterserver: becoming a daemon ... bye, bye\n");
		if ( (temp_pid = fork()) < 0) {
			ERRORV("fork() (errno: %d - %s)\n", errno, strerror(errno));
			return -1;
		} else if (temp_pid != 0) {
			exit(0);
		}

		retval = setsid();
		if (retval == -1) {
			ERRORV("setsid() (errno: %d - %s)\n", errno, strerror(errno));
			exit(-1);
		}

		retval = chdir("/");
		if (retval == -1) {
			ERRORV("chdir() (errno: %d - %s)\n", errno, strerror(errno));
			exit(1);
		}

		umask(0);

		if (option_logfile == 0) {
			if (freopen("/dev/null", "a", stdout) != stdout) {
				ERRORV("freopen() (errno: %d - %s)\n", errno, strerror(errno));
				return -1;
			}
		}
	}

	// check if user specified an alternative plugin dir
	// if he did well we set already set it above
	// else we set the default here
	if (!option_plugin_dir)
		masterserver_plugin_dir = MASTERSERVER_LIB_DIR;

	// load all libs in plugin_dir
	num_plugins = load_plugins(masterserver_plugin_dir, handle);
	if (num_plugins <= 0) {
		ERRORV("no plugins found in \"%s\"\n", masterserver_plugin_dir);
		return -1;
	}

	// print out a summary
	INFO("%d plugins loaded\n", num_plugins);

	// create sockets and bind them
	// had to be done because threads inherit the original user
	// and we don't want the threads to be root
	// TODO: sanity checks (e.g. duplicate ports)
	// TODO: check for plugin protocol
	j = &plugins;
	DEBUG("going to listen on %d interfaces ...\n", num_listen_interfaces);
	for (i = 0; i < num_plugins; i++) {
		if (*j == NULL) break;
		if ((*j)->enabled == 0) {
			WARNING("plugin nr %d %s disabled\n", i, (*j)->name);
			continue;
		}
	
		// create socket(s) for plugin
		for (k = 0; k < (*j)->num_ports; k++) {
			// fill sockaddr_in structure
			(*j)->server[k].sin_family = AF_INET;
			(*j)->server[k].sin_port = htons((*j)->port[k]); // port number from plugin
			(*j)->server[k].sin_addr.s_addr = htonl(INADDR_ANY);

			for (l = 0; l < num_listen_interfaces; l++, (*j)->num_sockets++) {
				(*j)->socket_d = realloc((*j)->socket_d, ((*j)->num_sockets+1)*sizeof(int));
				if ((*j)->socket_d == NULL) {
					ERRORV("realloc() failed trying to get %d bytes\n",
							(*j)->num_sockets+1*sizeof(int));
					exit(-1);
				}

				(*j)->socket_d[(*j)->num_sockets] = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
				DEBUG("plugin #%d %s | socket_d[%d] is %d\n", i, (*j)->name,
						(*j)->num_sockets, (*j)->socket_d[(*j)->num_sockets]);

				// receive broadcast packets
				retval = setsockopt((*j)->socket_d[(*j)->num_sockets], SOL_SOCKET,
						SO_BROADCAST, &setsockopt_temp, sizeof(setsockopt_temp));
				if (retval == -1) {
					ERRORV("setsockopt() (errno: %d - %s)\n", errno,
							strerror(errno));
					return -1;
				}

				// bind socket to the interfaces specified in -i
				if (option_bind_to_interface) {
					DEBUG("setsockopt(..., \"%s\", %d+1);\n",
							listen_interface[l], strlen(listen_interface[l]));
					retval = setsockopt((*j)->socket_d[(*j)->num_sockets],
							SOL_SOCKET, SO_BINDTODEVICE, listen_interface[l],
							strlen(listen_interface[l])+1);
					if (retval == -1) {
						ERRORV("setsockopt() (errno: %d - %s)\n", errno,
								strerror(errno));
						return -1;
					}
					DEBUG("%s socket #%d successfully bound to %s\n",
							(*j)->name, (*j)->num_sockets, listen_interface[l]);
					INFO("listening on %s UDP port %d\n", listen_interface[l],
							(*j)->port[k]);
				} else INFO("listening on UDP port %d\n", (*j)->port[k]);

				// bind socket to structure
				retval = bind((*j)->socket_d[(*j)->num_sockets],
						(struct sockaddr *) &(*j)->server[k],
						sizeof(struct sockaddr_in));
				if (retval == -1) {
					ERRORV("bind() (errno: %d - %s)\n", errno, strerror(errno));
					return -1;
				}
			}
		}
		j = &(*j)->next;
	}
	DEBUG("sockets successfully created and bound\n");

	if (option_bind_to_interface) give_up_root_privileges();

	// main part
	DEBUG("creating plugin threads...\n");
	j = &plugins;
	for (i = 0; i < num_plugins; i++) {
		if (*j == NULL) break;
		if ((*j)->enabled == 0) continue;

		// create plugin thread
		retval = pthread_create(&(*j)->thread_nr, NULL, (void *) plugin_thread, (void *) *j);
		if (retval != 0) {
			switch(retval) {
				case EAGAIN:
					ERROR("pthread_create returned an error; not enough system"
						" resources to create a process for the new thread\n");
					ERRORV("or more than %d threads are already active\n", PTHREAD_THREADS_MAX);
					return -1;
			}
		}
		INFO("created %s plugin thread\n", (*j)->name);
		j = &(*j)->next; // point j to next plugin in linked list
	}

	// create heartbeat threads
	DEBUG("creating heartbeat threads...\n");
	j = &plugins;
	for (i = 0; i < num_plugins; i++) {
		if (*j == NULL) break;
		if ((*j)->enabled == 0) continue;

		retval = pthread_create(&(*j)->heartbeat_thread_nr, NULL,
				(void *) plugin_heartbeat_thread, (void *) *j);
		if (retval != 0) {
			switch(retval) {
				case EAGAIN:
					ERROR("pthread_create returned an error; not enough system"
						" resources to create a process for the new thread\n");
					ERRORV("or more than %d threads are already active\n", PTHREAD_THREADS_MAX);
	                return -1;
			}
		}
		INFO("created heartbeat thread for %s\n", (*j)->name);
		j = &(*j)->next;
	}

	// cleanup and exit
	// (not really; this is just to stop the parent from eating cpu time)
	// XXX: paranoid cleanup ?
	//		check if pointers are != NULL
	//		destroy mutexes
	//		free private data
	INFO("joining plugin threads for graceful cleanup/shutdown... \n");
	for (j = &plugins; *j; j = &(*j)->next) {
		DEBUG("joining thread #%ld\n", (*j)->thread_nr);
		retval = pthread_join((*j)->thread_nr, NULL);
		if (retval != 0) {
			ERROR("pthread_join()\n");
			return -1;
		}
		DEBUG("thread #%ld exited; cleaning up...\n", (*j)->thread_nr);
		// free private data
		// to really free all private data we have to call a cleanup function
		// of the plugin
		if (&(*j)->cleanup != NULL) (*j)->cleanup();

		// free server list
		free((*j)->list);
		for (i = 0; i < (*j)->num_sockets; i++) close((*j)->socket_d[i]);
		if ((*j)->num_msgs > 0)
			for (i = 0; i < (*j)->num_msgs; i++) free((*j)->msg_out[i]);
		free((*j)->msg_out);
		free((*j)->msg_out_length);
		DEBUG("thread #%ld clean up successful\n", (*j)->thread_nr);
	}

	DEBUG("closing dynamic libs ...\n");
	for (; num_plugins > 0; num_plugins--)
		dlclose(&handle[num_plugins]);
	DEBUG("dynamic libs successfully closed\n");

	// TODO: check retval ?
	log_close();
	return 0;
}

void
plugin_thread(void *arg)
{
	int retval; // temp var for return values
	int i, j, k;
	char *msg_in; // buffer for incoming packet
	struct masterserver_plugin *me = (struct masterserver_plugin *) arg;
	int client_len = sizeof(me->client);
	int n = 0; // for select()
	fd_set rfds;

	DEBUG("%s_thread: hello world\n", me->name);

	msg_in = calloc(MAX_PKT_LEN, sizeof(char));
	if (msg_in == NULL) {
		ERROR("not enough memory for incoming packet buffer\n");
		pthread_exit((void *) -1);
	}

	// main loop
	while (1) {
		FD_ZERO(&rfds);
		for (i = 0; i < me->num_sockets; i++) {
			if (me->socket_d[i] > n) n = me->socket_d[i];
			FD_SET(me->socket_d[i], &rfds);
		}
		retval = select(n+1, &rfds, NULL, NULL, NULL);
		if (retval == -1) {
			ERRORV("%s_thread: select() (errno: %d - %s)\n", me->name, errno,
					strerror(errno));
			pthread_exit((void *) 1);
		}
		for (i = 0; i < me->num_sockets; i++) {
			if (FD_ISSET(me->socket_d[i], &rfds)) {
				retval = recvfrom(me->socket_d[i], msg_in, MAX_PKT_LEN, 0,
						(struct sockaddr *) &me->client, &client_len);
				if (retval == -1) {
					ERRORV("%s_thread: recvfrom() (errno: %d - %s)\n", me->name,
							errno, strerror(errno));
					ERRORV("%s_thread: socket_d is %d\n", me->name,
							me->socket_d[i]);
					ERRORV("%s_thread: MAX_PKT_LEN is %d\n",
						me->name, MAX_PKT_LEN);
					pthread_exit((void *) 1);
				}
				DEBUG("%d bytes received\n", retval);

				DEBUG("locking mutex\n");
				retval = pthread_mutex_lock(&me->mutex);
				if (retval != 0) {
					ERRORV("%s_thread: pthread_mutex_lock() (retval: %d)\n",
							me->name, retval);
					pthread_exit((void *) -1);
				}
				DEBUG("mutex succesfully locked\n");

				// TODO: create new thread
				retval = me->process(msg_in);
				if (retval == -2) {
					ERRORV("%s_thread: plugin reported: not enough memory for an outgoing packet\n", me->name);
					// TODO: cleanup?
					pthread_exit((void *) -1);
				} else if (retval == -1) {
					//WARNING("%s_thread: plugin reported: invalid packet received\n", me->name);
				} else if (retval == 0) {
					//INFO("%s_thread: plugin reported: server successfully added\n", me->name);
				} else if (retval == 1) {
					DEBUG("me->num_msgs is %d\n", me->num_msgs);
					for (k = 0; k < me->num_msgs; k++)
						DEBUG("me->msg_out_length[%d] is %d\n", k, me->msg_out_length[k]);
					DEBUG("sending %d packets to %s:%u\n",
							me->num_msgs, inet_ntoa(me->client.sin_addr),
							ntohs(me->client.sin_port));

					for (j = 0; j < me->num_msgs; j++) {
						retval = sendto(me->socket_d[i], me->msg_out[j],
								me->msg_out_length[j], 0,
								(struct sockaddr *) &me->client, client_len);
						if (retval == -1) {
							ERRORV("sendto() (errno: %d - %s)\n",
									errno, strerror(errno));
						} else DEBUG("%d bytes sent\n", retval);
					}
				} else if (retval == 2) {
					// INFO("%s_thread: plugin reported: server deleted\n", me->name);
				}

				// clean up
				memset(msg_in, 0, MAX_PKT_LEN);
				if (me->num_msgs > 0) {
					DEBUG("freeing outgoing packets\n");
					for (j = 0; j < me->num_msgs; j++)
						if (me->msg_out[j] != NULL)
							free(me->msg_out[j]);
					me->num_msgs = 0;
					free(me->msg_out);
					free(me->msg_out_length);
					me->msg_out = NULL;
					me->msg_out_length = NULL;
				}

				DEBUG("unlocking mutex\n");
				retval = pthread_mutex_unlock(&me->mutex);
				if (retval != 0) {
					ERROR("pthread_mutex_unlock()\n");
					pthread_exit((void *) -1);
				}
			} // if(FD_ISSET())
		} // for(i)
	} // end while(1)
}

void
plugin_heartbeat_thread(void *arg)
{
	struct masterserver_plugin *me = (struct masterserver_plugin *) arg;
	int i = 0;
	int heartbeat_diff = 0;
	int retval; // temp var for return values

	DEBUG("%s_heartbeat_thread: hello world\n", me->name);

	// main loop
	while (1) {
		DEBUG("sleeping %d seconds ...\n", me->heartbeat_timeout);
		sleep(me->heartbeat_timeout);
		DEBUG("waking up\n");

		DEBUG("locking plugin mutex\n");
		retval = pthread_mutex_lock(&me->mutex);
		if (retval != 0) {
			ERROR("pthread_mutex_lock()\n");
			pthread_exit((void *) -1);
		}

		for (i = 0; i < me->num_servers; i++) {
			heartbeat_diff = time(NULL) - me->list[i].lastheartbeat;
			if (heartbeat_diff > 300) {
				INFO("%s_heartbeat_thread: server %s:%d died (heartbeat_diff %d)\n",
					me->name, inet_ntoa(me->list[i].ip), ntohs(me->list[i].port), heartbeat_diff);
				delete_server(me, i);
				i--;
			} else {
				DEBUG("server %s:%d is alive (heartbeat_diff %d)\n",
						inet_ntoa(me->list[i].ip), ntohs(me->list[i].port),
						heartbeat_diff);
			}
		}

		DEBUG("unlocking mutex\n");
		retval = pthread_mutex_unlock(&me->mutex);
		if (retval != 0) {
			ERROR("pthread_mutex_unlock\n");
			pthread_exit((void *) -1);
		}
	} // end while(1)
}

extern void
delete_server(struct masterserver_plugin *me, int server_num)
{
	int i = server_num;

	me->num_servers--;
	me->list[i].ip = me->list[me->num_servers].ip;
	me->list[i].port = me->list[me->num_servers].port;
	me->list[i].lastheartbeat = me->list[me->num_servers].lastheartbeat;
	me->list[i].private_data = me->list[me->num_servers].private_data;

	DEBUG("reallocating server list (old size: %d -> new size: %d)\n",
			(me->num_servers+2)*sizeof(serverlist_t),
			(me->num_servers+1)*sizeof(serverlist_t));
	me->list = (serverlist_t *) realloc(me->list, (me->num_servers + 1) * sizeof(serverlist_t));
	if (me->list == NULL) {
		ERROR("(__)\n");
		ERROR(" °°\\\\\\~\n");
		ERROR("  !!!!\n");
		pthread_exit((void *) -1);
	}
	DEBUG("reallocation successful\n");
}

