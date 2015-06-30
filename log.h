#ifndef LOG_H
#define LOG_H
#include <stdio.h>

// This log is for proxy client and main() function
// Caution: this log is just for debug purpose.
// And SHOULD NOT open when running for proxy client.
// Since it will exceeds the sshd's max length limitation
#define __DEBUG_LOG__ 1
#define DEBUG_LOG(fmt, arg...)                                          \
    if (__DEBUG_LOG__) {                                                \
        printf ("[DEBUG:%s:%d] "fmt"\n", __FILE__, __LINE__, ##arg);    \
    }



#endif
