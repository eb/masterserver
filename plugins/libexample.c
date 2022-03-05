#include "../masterserver.h"

#define EXAMPLE_PORT 27950
#define EXAMPLE_PLUGIN_VERSION "0.1"
#define HEARTBEAT_TIMEOUT 30 // value is in seconds

static void info(void);
static int process(char *packet); // process packet and return a value


static
struct masterserver_plugin example
= { NULL,
	"example",
	EXAMPLE_PLUGIN_VERSION,
	MASTERSERVER_VERSION,
	EXAMPLE_PORT,
	HEARTBEAT_TIMEOUT,
	PTHREAD_MUTEX_INITIALLIZER,
	&info,
	&process
};

static void
info(void)
{
	fprintf(stdout,
"example masterserver plugin v%s\n"
"  compiled for masterserver v%s\n", EXAMPLE_PLUGIN_VERSION, MASTERSERVER_VERSION);
}

static unsigned int
process(char *packet)
{
	return 0;
}

void
_init(void)
{
	register_plugin(&example);
}

