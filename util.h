// Define the basic util functions
// The printing time utils are cited from tcpdump source code and from Internet.
// (e.g. gmt2local)
//
#ifndef UTIL_H
#define UTIL_H
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>

#include "log.h"

/* ethernet headers length */
#define SIZE_ETHERNET 14
#define SEARCH_STRING_LEN 128
#define RES_STRING_LEN 256


const static int FILE_LEN = 1024;

int32_t gmt2local(time_t t);

char * ts_format(int sec, int usec);

void ts_print(const struct timeval *tvp);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

int create_injection_socket(char *interface);

#endif
 
