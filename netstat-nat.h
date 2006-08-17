/*
#-------------------------------------------------------------------------------
#                                                                                                                         
# $Id: netstat-nat.h,v 1.12 2006/08/17 17:43:25 danny Exp $     
#       
#                                                                                                                  
# Copyright (c) 2006 by D.Wijsman (danny@tweegy.nl). 
# All rights reserved.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option)
# any later version.
# 
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
#	       
#                                                                                                                         
#-------------------------------------------------------------------------------
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <regex.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <strings.h>

//#define VERSION		"1.4.4"
#define ROWS		6


int get_protocol(char *line, char *protocol);
int get_connection_state(char *line, char *state);
void process_entry(char *line);
void check_src_dst(char *protocol, char *src_ip, char *dst_ip, char *src_port, char *dst_port, char *status);
void store_data(char *protocol, char *src_ip, char *dst_ip, char *src_port, char *dst_port, char *status);
void extract_ip(char *gen_buffer);
void display_help();
int lookup_hostname(char **r_host);
int lookup_ip(char *hostname, size_t hostname_size);
//int match(char *string, char *pattern);
int check_if_source(char *host);
int check_if_destination(char *host);
void lookup_portname(char **port, char *proto);
void oopsy(int size);
static void *xrealloc(void *oldbuf, size_t newbufsize);
static void *xcalloc(size_t bufsize);
void get_protocol_name(char *protocol_name, int protocol_nr);

#define strcopy(dst, dst_size, src) \
	strncpy(dst, src, (dst_size - 1)); 

/* The End */
