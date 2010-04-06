#ifndef __LOG_H_
#define __LOG_H_

#ifdef _TUN_MGR_DEBUG
#define dprintf eprintf
#else
#define dprintf(...) do { } while(0)
#endif

#define eprintf(X, ...) fprintf(fLog, __FILE__ " [%d] - "  X, __LINE__, ##__VA_ARGS__)
#define Eprintf(X, ...) fprintf(stderr, __FILE__ " [%d] - "  X, __LINE__, ##__VA_ARGS__)

extern FILE* fLog;
void open_log_file(char szLogFile[]);

#endif /* __LOG_H */
