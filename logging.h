#ifndef _LOGGING_H
#define _LOGGING_H

#define LOG_LEVEL_INFO		0
#define LOG_LEVEL_WARNING	1
#define LOG_LEVEL_ERROR		2
#define LOG_LEVEL_DEBUG		3

#define INFO(fmt, args...) \
		log_write(LOG_LEVEL_INFO, LOG_SUBNAME, fmt, ##args);
	/*if (_log_level <= LOG_LEVEL_INFO) \*/
#define WARNING(fmt, args...) \
		log_write(LOG_LEVEL_WARNING, LOG_SUBNAME, fmt, ##args);
	/*if (_log_level <= LOG_LEVEL_WARNING) \*/
#define ERROR(fmt) \
		log_write(LOG_LEVEL_ERROR, LOG_SUBNAME, "in %s near line %d: "fmt, __FILE__, __LINE__);
	/*if (_log_level <= LOG_LEVEL_ERROR) \*/
#define ERRORV(fmt, args...) \
		log_write(LOG_LEVEL_ERROR, LOG_SUBNAME, "in %s near line %d: "fmt, __FILE__, __LINE__, ##args);
	/*if (_log_level <= LOG_LEVEL_ERROR) \*/

#ifdef DEBUG
#undef DEBUG
#define DEBUG(fmt, args...) if (debug == 1) log_write(LOG_LEVEL_DEBUG, LOG_SUBNAME, fmt, ##args);
#else
#undef DEBUG
#define DEBUG(fmt, args...)
#endif

#define LOG_SUBNAME "default"

//extern int _log_level;

extern int log_init(char *, char*);
extern void log_write(int, char *, char *, ...);
extern void log_close(void);

#endif // _LOGGING_H

