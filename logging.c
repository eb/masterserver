/* logging.c: Logging code for masterserver. */
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
#include <stdarg.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "logging.h"

#define DEFAULT_LOGFILE "/var/log/masterserver.log"
#define DEFAULT_FILEMODE (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define DEFAULT_FILEFLAGS (O_CREAT | O_RDWR)
#define DEFAULT_PROGNAME "masterserver"

char *default_logfile = NULL;	// can be set from main(); fallback to DEFAULT_LOGFILE
char *default_progname = NULL;
int _lfd = 0;	// global file descriptor where debug messages go
FILE *_lfp = NULL;	// global file pointer where debug messages go

int _log_level = 0;

int log_init(char *filename, char *progname) 
{
	default_progname = progname != NULL ? strdup(progname) : strdup(DEFAULT_PROGNAME);
	if (filename != NULL) {
		default_logfile = strdup(filename);
		_lfd = open(default_logfile, DEFAULT_FILEFLAGS, DEFAULT_FILEMODE);
		if (_lfd == -1) {
			fprintf(stderr, "%s, %d: %s %s", __FILE__, __LINE__, default_logfile, strerror(errno));
			return -1;
		}

		_lfp = fdopen(_lfd, "a");
		if (_lfp == NULL) {
			fprintf(stderr, "%s, %d: %s", __FILE__, __LINE__, strerror(errno)); // redundant, maybe stderr is closed
			return -1;
		}
	} else {
		_lfp = stdout;
	}
	return 0;
}

void log_write(int log_level, char *subname, char *fmt, ...) {
	time_t t;
	struct tm *tm_now;
	va_list tmp;

	t = time(NULL);
	tm_now = localtime(&t);

	fprintf(_lfp, "[%.2d.%.2d.%d %.2d:%.2d:%.2d] %s:%s ", 
		tm_now->tm_mday, tm_now->tm_mon + 1, tm_now->tm_year + 1900,
		tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec,
		default_progname, subname);

	switch (log_level) {
		case LOG_LEVEL_INFO:
			fprintf(_lfp, "info: ");
			break;
		case LOG_LEVEL_WARNING:
			fprintf(_lfp, "warning: ");
			break;
		case LOG_LEVEL_ERROR:
			fprintf(_lfp, "Error: ");
			break;
		case LOG_LEVEL_DEBUG:
			fprintf(_lfp, "Debug: ");
			break;
	}

	va_start(tmp, fmt);
	vfprintf(_lfp, fmt, tmp);
	va_end(tmp);

	fflush(_lfp); // write it to disk
}


void log_close(void) 
{
	if (close(_lfd) == -1) {
		fprintf(stderr, "%s, %d: %s", __FILE__, __LINE__, strerror(errno)); // redundant, maybe stderr is closed
		return;     
	}
}

