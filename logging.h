#ifndef _LOGGING_H
#define _LOGGING_H

#define LOG_LEVEL_INFO		0
#define LOG_LEVEL_WARNING	1
#define LOG_LEVEL_ERROR		2
#define LOG_LEVEL_DEBUG		3

#define INFO(fmt, args...)		log_write(LOG_LEVEL_INFO, LOG_SUBNAME, fmt, ##args);
#define WARNING(fmt, args...)	log_write(LOG_LEVEL_WARNING, LOG_SUBNAME, fmt, ##args);
#define ERROR(fmt)				log_write(LOG_LEVEL_ERROR, LOG_SUBNAME, "in %s near line %d: "fmt, __FILE__, __LINE__);
#define ERRORV(fmt, args...)	log_write(LOG_LEVEL_ERROR, LOG_SUBNAME, "in %s near line %d: "fmt, __FILE__, __LINE__, ##args);

#ifdef DEBUG
#undef DEBUG
#define DEBUG(fmt, args...) if (debug == 1) log_write(LOG_LEVEL_DEBUG, LOG_SUBNAME, fmt, ##args);
#else
#undef DEBUG
#define DEBUG(fmt, args...)
#endif

#define LOG_SUBNAME "default"

extern int log_init(char *filename, char* progname);
extern void log_write(int log_level, char *subname, char *fmt, ...);
extern void log_close(void);

#endif // _LOGGING_H

