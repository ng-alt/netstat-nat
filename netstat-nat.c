/*
#-------------------------------------------------------------------------------
#                                                                                                                         
# $Id: netstat-nat.c,v 1.11 2002/07/12 20:05:54 mardan Exp $     
#       
# $Log: netstat-nat.c,v $
# Revision 1.11  2002/07/12 20:05:54  mardan
# Added argument for extended view of hostnames.
# Moved display-code into one function.
# Removed most unnessacery code.
# Updated README
#
# Revision 1.10  2002/07/10 19:58:33  mardan
# Added filtering by destination-host, re-arranged some code to work properly.
# Tested DNAT icmp and udp.(pls report if any bugs occur)
# Fixed a few declaration bugs.
#
# Revision 1.9  2002/07/09 20:00:36  mardan
# Added fully DNAT support (udp & icmp not fully tested yet, but should work),
# including argument support for (S)(D)NAT selection.
# Re-arranged layout code, can possible merged into one function.
# Some few minor changes.
# Started to work on destination-host selection.
#
# Revision 1.8  2002/07/07 20:27:47  mardan
# Added display by source host/IP.
# Made a few fixes/changes.
# Updated the REAMDE.
#
# Revision 1.7  2002/06/30 19:55:41  mardan
# Added README and COPYING (license) FILES.
#
# Revision 1.6  2002/06/23 16:27:26  mardan
# Finished udp.
# Maybe some layout changes in future? therwise tool is finished.
#
# Revision 1.5  2002/06/23 14:07:46  mardan
# Added protocol arg option.
# Todo: udp protocol
#
# Revision 1.4  2002/06/23 12:57:35  mardan
# Added ident strings for test :-)
#
# Revision 1.3  2002/06/23 12:47:08  mardan
# Fixed resolved hostname hussle-up/layout
# Moved all source code into netstat-nat.c
#
# Revision 1.2  2002/06/23 11:56:09  mardan
# Added NAT icmp display.
# Still need to do udp (more states possible)
# Really need to fix resolved hostnames display, still hussled up.
#
# Revision 1.1.1.1  2002/05/04 01:08:06  mardan
# Initial import of netstat-nat, the C version.
# Array pointers really needs to be fixed, still lots of other bugs..
# So far only TCP displayed.
# No commandline args for e.g. no_nameresolving, protocol.
#
#
#                                                                                                                  
# Copyright (c) 2002 by D.Wijsman (mardan@tweegy.demon.nl). 
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
#include <string.h>
#include <regex.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>

static char const rcsid[] = "$Id: netstat-nat.c,v 1.11 2002/07/12 20:05:54 mardan Exp $";
static char const rcsname[] = "$Author: mardan $";
static int RESOLVE = 1;
static char PROTOCOL[4] = "";
static char SRC_IP[35] = "";
static char DST_IP[35] = "";
static int SNAT = 1;
static int DNAT = 1;
static int EXT_VIEW = 0;
int main(argc, argv)
int argc;

char *argv[];
    {
    int c;
    const char *args = "hnp:s:d:SDx";
    int ret;
    int argerr;
    FILE *f;
    char line[200];
    // check parameters
    while ((c = getopt(argc, argv, args)) != -1 ) {
	switch (c) {
	case 'h':
	    printf("args: -h: displays this help\n");
	    printf("      -n: don't resolve hostnames\n");
	    printf("      -p tcp | udp | icmp  : display selected protocol\n");
	    printf("      -s <source-host>     : display connections by source\n");
	    printf("      -d <destination-host>: display connections by destination\n");
	    printf("      -S: display SNAT connections\n");
	    printf("      -D: display DNAT connections (default: SNAT & DNAT)\n"); 
	    printf("      -x: extended hostnames view\n");
	    return 1;
	case 'n':
	    RESOLVE = 0;
	    break;
	case 'p':
	    strcpy (PROTOCOL, optarg);
	    break;
	case 's':
	    strcpy (SRC_IP, optarg);
	    lookup_ip(SRC_IP);
	    break;
	case 'd':
	    strcpy (DST_IP, optarg);
	    lookup_ip(DST_IP);
	    break;    
	case 'S':
	    DNAT = 0;
	    break;
	case 'D':
	    SNAT = 0;
	    break;
	case 'x':
	    EXT_VIEW = 1;
	    break;
	}
    }
    
    // some checking for IPTables and read file
    f=fopen("/proc/net/ip_conntrack","r");
    if (!f) {
	printf("Make sure netfilter/IPtables is enabled by kernel or modules.\n");
	return 1;
	}
    
    // process conntrack table
    if (!EXT_VIEW) {
	printf("%-6s%-25s%-25s%-13s%-6s","Proto","NATed Address","Foreign Address","Ports","State\n");
    } else {
	printf("%-6s%-35s%-35s%-13s%-6s","Proto","NATed Address","Foreign Address","Ports","State\n");
	}
    while (fgets(line,1000,f)!=NULL) {
	if ((!strcmp(PROTOCOL, "tcp")) || (!strcmp(PROTOCOL, ""))) {
	    if(match(line, "tcp")) {
		protocol_tcp(line);
		}
	    }
	    
	if ((!strcmp(PROTOCOL, "udp")) || (!strcmp(PROTOCOL, ""))) {
	    if((match(line, "udp")) && (match(line, "UNREPLIED"))) {
		protocol_udp_unr(line);
		}
	    if((match(line, "udp")) && (match(line, "ASSURED"))) {
		protocol_udp_ass(line);
		}
	    if((match(line, "udp")) && (!match(line, "ASSURED")) && (!match(line, "UNREPLIED"))) {
		protocol_udp(line); 
		}
	    }
	        
	if ((!strcmp(PROTOCOL, "icmp")) || (!strcmp(PROTOCOL, ""))) {
	    if((match(line, "icmp")) && (match(line, "UNREPLIED"))) {
		protocol_icmp_unr(line);
		}
	    if((match(line, "icmp")) && (!match(line, "UNREPLIED"))) {
		protocol_icmp_rep(line);
		}
	    }
	}
    fclose(f);
    return 0;
    }

// -- NATed protocols

// NATed tcp protocol
int protocol_tcp(char *line)
    {
    char *token;
    char *buf[35];
    int count;
    token = strtok(line," ");
    count = 0;

    while(token != NULL) {
	buf[count] = token;
	if(!strlen(buf[count]))
	    buf[count]="";
	count++;
	token = strtok(NULL," ");
	}
    if ((match(buf[4], "=")) && (match(buf[5], "=")) && (match(buf[8], "=")) && (match(buf[9], "="))) {
	extract_ip(buf[4]);
	extract_ip(buf[9]);
	extract_ip(buf[5]);
	extract_ip(buf[8]);
	if (SNAT) {
	    if ((!strcmp(buf[4],buf[9])==0) && (strcmp(buf[5],buf[8])==0)) {		
		check_src_dst(buf[0],buf[4],buf[8],buf[6],buf[7],buf[3]);
		}
	    }
	if (DNAT) {
	    if ((strcmp(buf[4],buf[9])==0) && (!strcmp(buf[5],buf[8])==0)) {		
		check_src_dst(buf[0],buf[4],buf[8],buf[6],buf[7],buf[3]);
		}
	    }
	}
    return(1);
    }

// NATed udp protocol
int protocol_udp(char *line) 
    {
    char *token;
    char *buf[35];
    int count;
    token = strtok(line," ");
    count = 0;
    
    while(token != NULL) {
	buf[count] = token;
	if(!strlen(buf[count]))
	    buf[count]="";
	count++;
	token = strtok(NULL," ");
 	}
    if ((match(buf[2], "=")) && (match(buf[3], "=")) && (match(buf[6], "=")) && (match(buf[6], "="))) {
        extract_ip(buf[2]);
	extract_ip(buf[3]);
	extract_ip(buf[6]);
	extract_ip(buf[7]);
	if (SNAT) {
	    if ((!strcmp(buf[2],buf[7])==0) && (strcmp(buf[3],buf[6])==0)) {	
		check_src_dst(buf[0],buf[2],buf[6],buf[4],buf[5]," ");
		}    
	    }
	if (DNAT) {
	    if ((strcmp(buf[2],buf[7])==0) && (!strcmp(buf[3],buf[6])==0)) {	
		check_src_dst(buf[0],buf[2],buf[6],buf[4],buf[5]," ");
		}    
	    }	
	}
    return(1);
    }

int protocol_udp_ass(char *line) 
    {
    char *token;
    char *buf[35];
    int count;
    token = strtok(line," ");
    count = 0;
    
    while(token != NULL) {
	buf[count] = token;
	if(!strlen(buf[count]))
	    buf[count]="";
	count++;
	token = strtok(NULL," ");
 	}
    if ((match(buf[3], "=")) && (match(buf[4], "=")) && (match(buf[7], "=")) && (match(buf[8], "="))) {
        extract_ip(buf[3]);
	extract_ip(buf[4]);
	extract_ip(buf[7]);
	extract_ip(buf[8]);
	if(SNAT) {
	    if ((!strcmp(buf[3],buf[8])==0) && (strcmp(buf[4],buf[7])==0)) {	
		check_src_dst(buf[0],buf[3],buf[7],buf[5],buf[6],buf[11]);
		}    
	    }
	if(DNAT) {
	    if ((strcmp(buf[3],buf[8])==0) && (!strcmp(buf[4],buf[7])==0)) {	
		check_src_dst(buf[0],buf[3],buf[7],buf[5],buf[6],buf[11]);
		}    
	    }
	}
    return(1);
    }

int protocol_udp_unr(char *line) 
    {
    char *token;
    char *buf[35];
    int count;
    token = strtok(line," ");
    count = 0;
    
    while(token != NULL) {
	buf[count] = token;
	if(!strlen(buf[count]))
	    buf[count]="";
	count++;
	token = strtok(NULL," ");
 	}
    if ((match(buf[3], "=")) && (match(buf[4], "=")) && (match(buf[8], "=")) && (match(buf[9], "="))) {
        extract_ip(buf[3]);
	extract_ip(buf[4]);
	extract_ip(buf[8]);
	extract_ip(buf[9]);
	if (SNAT) {
	    if ((!strcmp(buf[3],buf[9])==0) && (strcmp(buf[4],buf[8])==0)) {	
		check_src_dst(buf[0],buf[3],buf[8],buf[5],buf[6],buf[7]);
		}    
	    }
	if (DNAT) {
	    if ((strcmp(buf[3],buf[9])==0) && (!strcmp(buf[4],buf[8])==0)) {	
		check_src_dst(buf[0],buf[3],buf[8],buf[5],buf[6],buf[7]);
		}    
	    }
	}
    return(1);
    }

// NATed icmp protocol
int protocol_icmp_unr(char *line) 
    {
    char *token;
    char *buf[35];
    int count;
    token = strtok(line," ");
    count = 0;
    
    while(token != NULL) {
	buf[count] = token;
	if(!strlen(buf[count]))
	    buf[count]="";
	count++;
	token = strtok(NULL," ");
 	}
    if ((match(buf[3], "=")) && (match(buf[4], "=")) && (match(buf[9], "=")) && (match(buf[10], "="))) {
        extract_ip(buf[3]);
        extract_ip(buf[10]);
        extract_ip(buf[4]);
        extract_ip(buf[9]);
        if (SNAT) {
	    if ((!strcmp(buf[3],buf[10])==0) && (strcmp(buf[4],buf[9])==0)) {	
		check_src_dst(buf[0],buf[3],buf[9]," "," ",buf[8]);
    		}
	    }
	if (DNAT) {
	    if ((strcmp(buf[3],buf[10])==0) && (!strcmp(buf[4],buf[9])==0)) {	
    		check_src_dst(buf[0],buf[3],buf[9]," "," ",buf[8]);
		}    
	    }
	}
    return(1);
    }

int protocol_icmp_rep(char *line) 
    {
    char *token;
    char *buf[35];
    int count;
    token = strtok(line," ");
    count = 0;
    
    while(token != NULL) {
	buf[count] = token;
	if(!strlen(buf[count]))
	    buf[count]="";
	count++;
	token = strtok(NULL," ");
 	}
    if ((match(buf[3], "=")) && (match(buf[4], "=")) && (match(buf[8], "=")) && (match(buf[9], "="))) {
        extract_ip(buf[3]);
	extract_ip(buf[9]);
	extract_ip(buf[4]);
	extract_ip(buf[8]);
	if (SNAT) {
	    if ((!strcmp(buf[3],buf[9])==0) && (strcmp(buf[4],buf[8])==0)) {	
		check_src_dst(buf[0],buf[3],buf[9]," "," ","[REPLIED]");
		}
	    }
	if (DNAT) {
	    if ((strcmp(buf[3],buf[9])==0) && (!strcmp(buf[4],buf[8])==0)) {	
		check_src_dst(buf[0],buf[3],buf[9]," "," ","[REPLIED]");
		}
	    }
	}
    return(1);
    }
    
// -- End of NATed protocols

// -- Internal used functions
// Check filtering by source and destination IP
int check_src_dst(char *protocol, char *src_ip, char *dst_ip, char *src_port, char *dst_port, char *status) 
    {
    if ((check_if_source(src_ip)) && (strcmp(DST_IP,"")==0)) {
	print_connection(protocol,src_ip,dst_ip,src_port,dst_port,status);
	}
    else if ((check_if_destination(dst_ip)) && (strcmp(SRC_IP,"")==0)) {
	print_connection(protocol,src_ip,dst_ip,src_port,dst_port,status);
	}
    else if ((check_if_destination(dst_ip)) && (check_if_source(src_ip))) {
	print_connection(protocol,src_ip,dst_ip,src_port,dst_port,status);
	}
    return(1);
    }

int print_connection(char *protocol, char *src_ip, char *dst_ip, char *src_port, char *dst_port, char *status)  
    {
    char gen_buffer[35] = "";
    char ports[12] = "";
    char *split;
    //protocol_layout(protocol);
    memcpy(gen_buffer, protocol, 5);
    printf("%-6s", gen_buffer);
    //sourceip_layout(src_ip);
    if (RESOLVE) {
        lookup_hostname(src_ip);}
    if (!EXT_VIEW) {
	memcpy(gen_buffer, src_ip, 24);
	printf("%-25s", gen_buffer);
    } else {
	memcpy(gen_buffer, src_ip, 34);
	printf("%-35s", gen_buffer);
	}
    //destip_layout(dst_ip);
    if (RESOLVE) {
        lookup_hostname(dst_ip);}
    if (!EXT_VIEW) {
	memcpy(gen_buffer, dst_ip, 24);
	printf("%-25s", gen_buffer);
    } else {
	memcpy(gen_buffer, dst_ip, 34);
	printf("%-35s", gen_buffer);
	}
    //port_layout(src_port, dst_port);
    if ((match(src_port, "=")) && (match(dst_port, "="))) {
	split = strtok(src_port,"=");
	split = strtok(NULL,"=");
	src_port = split;
	// destination port
	strncpy(ports, src_port, 5); 
	split = strtok(dst_port,"=");
	split = strtok(NULL,"=");
	dst_port = split;
	// port layout
	strcat(ports, "->");
	strncat(ports, dst_port, 5); 
	}
    printf("%-13s", ports);
    // status layout
    printf("%-10s", status);
    printf("\n");
    return(1);
    }

int extract_ip(char *gen_buffer) 
    {
    char *split;
    split = strtok(gen_buffer,"=");
    split = strtok(NULL,"=");
    strcpy(gen_buffer,split);
    return(1);
    }

int lookup_hostname(char *r_host) 
    {
    int addr;
    struct hostent *hp;
    char **p;
    char *hostname;
    addr = inet_addr (r_host);
    hp=gethostbyaddr((char *) &addr, sizeof (addr), AF_INET);
    if (hp == NULL) {
	return (0);
	}

    for (p = hp->h_addr_list; *p!=0;p++){
	struct in_addr in;
	char **q;
	(void)memcpy(&in.s_addr, *p, sizeof(in.s_addr));
	strcpy(r_host, "");
	strcpy(r_host,hp->h_name);
	}
    return (0);
    }

int lookup_ip(char *hostname)
    {
    char *ip;
    struct hostent *hp;
    struct in_addr ip_addr;
    hp = gethostbyname(hostname);
    if(!hp) {
	printf("Unknown host: %s\n",hostname);
	exit(-1);
	}
    ip_addr = *(struct in_addr *)(hp->h_addr);
    ip = inet_ntoa(*(struct in_addr *)(hp->h_addr));
    strcpy(hostname,ip);
    return(1);
    }

int match(char *string, char *pattern) 
    {
    int i;
    regex_t re;
    char buf[200];
    i=regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB);
    if (i != 0) {
	(void)regerror(i,&re,buf,sizeof buf);
	return(0);                       /* report error */
	}
    i = regexec(&re, string, (size_t) 0, NULL, 0);
    regfree(&re);
    if (i != 0) {
	(void)regerror(i,&re,buf,sizeof buf);
	return(0);                       /* report error */
	}
    return(1);
    }

int check_if_source(char *host) 
    {
    if ((strcmp(host,SRC_IP)==0) || (strcmp(SRC_IP, "")==0)) {
	return(1);
	}
    return(0);
    }

int check_if_destination(char *host) 
    {
    if ((strcmp(host,DST_IP)==0) || (strcmp(DST_IP, "")==0)) {
	return(1);
	}
    return(0);
    }

// -- End of internal used functions

// -- The End --
