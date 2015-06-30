/*
 * Copyright (C) 2004 toast
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 */
#include <pcre.h>
#include <libnet.h>

#define CONF_MAX_LEN 2048
#define CONF_MAX_RESPONSE 2048

typedef struct conf_entry
{
    char name[64];
    pcre *match;
    char *response;
    unsigned int response_len;
    struct conf_entry *next;
} conf_entry;


typedef struct user_data_t
{
    char * interface;
    conf_entry * conf;
    int inject_socket;
    libnet_ptag_t tcp_t;
    libnet_ptag_t ip_t;
    libnet_t *lnet;
    pcre *regexp;
} user_data;

conf_entry *parse_config_file(char *conf_file_path);
