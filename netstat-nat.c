/*
#-------------------------------------------------------------------------------
#                                                                                                                         
# $Id: netstat-nat.c,v 1.7 2002/06/30 19:55:41 mardan Exp $     
#       
# $Log: netstat-nat.c,v $
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
#include <sys/types.h>
#include <string.h>
#include <regex.h>
#include <netdb.h>
#include <unistd.h>

//#include <errno.h>

static char const rcsid[] = "$Id: netstat-nat.c,v 1.7 2002/06/30 19:55:41 mardan Exp $";
static char const rcsname[] = "$Author: mardan $";
static int RESOLVE;
static char PROTOCOL[] = "";


int main(argc, argv)
int argc;
char *argv[];
    {
    int c;
    const char *args = "h,n,p:proto";
    int  ret;
    int argerr;
    FILE *f;
    char line[200];
    RESOLVE = 1;
    // check paramters
    while ((c = getopt(argc, argv, args)) != -1 ) {
	switch (c) {
	case 'h':
	    printf("args: -h: prints this help\n");
	    printf("      -n: don't resolve IPs\n");
	    printf("      -p tcp | udp | icmp: prints only selected protocol\n");
	    return 1;
	case 'n':
	    RESOLVE = 0;
	    break;
	case 'p':
	    strcpy (PROTOCOL, optarg);
	    break;
	}
    }
    
    // some checking for IPTables and read file
    f=fopen("/proc/net/ip_conntrack","r");
    if (!f) {
	printf("Make sure IPTables is enabled by kernel or modules.\n");
	return 1;
	}
    
    // process conntrack table
    printf("Proto NATed Address            Foreign Address          Ports        State\n");
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
    char protocol[6]="";
    char src_ip[25]="", dst_ip[25]="";
    char ip_buffer[15]="", gen_buffer[25]="", port_buffer[5]=""; 
    char src_port[11]="", dst_port[11]="";
    char ports[15]="";
    char *token;
    char *split;
    char *buf[30];
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
	}
    else {
	buf[4]="";
	buf[5]="";
	buf[8]="";
	buf[9]="";
	}
    		
    if ((!strcmp(buf[4],buf[9])==0) && (strcmp(buf[5],buf[8])==0)) {		
	// protocol
	strcpy(gen_buffer, buf[0]);
	protocol_layout(gen_buffer);
	// source host
	strcpy(gen_buffer, buf[4]);
	sourceip_layout(gen_buffer);
	// destination host
	strcpy(gen_buffer, buf[5]);
	destip_layout(gen_buffer);
	//port_layout
	strcpy(src_port, buf[6]);
	strcpy(dst_port, buf[10]);
	port_layout(src_port, dst_port);
	// connection status
	printf("%-10s", buf[3]);
	// EOL
	printf("\n");
	}
    }

// NATed udp protocol
int protocol_udp(char *line) {
    char protocol[6]="";
    char src_ip[25]="", dst_ip[25]="";
    char ip_buffer[15]="", gen_buffer[25]="", port_buffer[5]=""; 
    char src_port[11]="", dst_port[11]="";
    char ports[15]="";
    char *token;
    char *split;
    char *buf[30];
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
	}
    else {
        buf[2]="";
        buf[3]="";
        buf[6]="";
        buf[7]="";
        }
    
    if ((!strcmp(buf[2],buf[7])==0) && (strcmp(buf[3],buf[6])==0)) {	
	// protocol
	strcpy(gen_buffer, buf[0]);
	protocol_layout(gen_buffer);
	// source host
	strcpy(gen_buffer, buf[2]);
	sourceip_layout(gen_buffer);
	// destination host
	strcpy(gen_buffer, buf[6]);
	destip_layout(gen_buffer);
	//port_layout
	strcpy(src_port, buf[4]);
	strcpy(dst_port, buf[5]);
	port_layout(src_port, dst_port);
	// connection status
	printf("%-10s", " ");
	// EOL
	printf("\n");	    
	}    
    }


int protocol_udp_ass(char *line) {
    char protocol[6]="";
    char src_ip[25]="", dst_ip[25]="";
    char ip_buffer[15]="", gen_buffer[25]="", port_buffer[5]=""; 
    char src_port[11]="", dst_port[11]="";
    char ports[15]="";
    char *token;
    char *split;
    char *buf[30];
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
	}
    else {
        buf[3]="";
        buf[4]="";
        buf[7]="";
        buf[8]="";
        }
    
    if ((!strcmp(buf[3],buf[8])==0) && (strcmp(buf[4],buf[7])==0)) {	
	// protocol
	strcpy(gen_buffer, buf[0]);
	protocol_layout(gen_buffer);
	// source host
	strcpy(gen_buffer, buf[3]);
	sourceip_layout(gen_buffer);
	// destination host
	strcpy(gen_buffer, buf[7]);
	destip_layout(gen_buffer);
	//port_layout
	strcpy(src_port, buf[5]);
	strcpy(dst_port, buf[6]);
	port_layout(src_port, dst_port);
	// connection status
	printf("%-10s", buf[11]);
	// EOL
	printf("\n");	    
	}    
    }


int protocol_udp_unr(char *line) {
    char protocol[6]="";
    char src_ip[25]="", dst_ip[25]="";
    char ip_buffer[15]="", gen_buffer[25]="", port_buffer[5]=""; 
    char src_port[11]="", dst_port[11]="";
    char ports[15]="";
    char *token;
    char *split;
    char *buf[30];
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
	}
    else {
        buf[3]="";
        buf[4]="";
        buf[8]="";
        buf[9]="";
        }
    
    if ((!strcmp(buf[3],buf[9])==0) && (strcmp(buf[4],buf[8])==0)) {	
	// protocol
	strcpy(gen_buffer, buf[0]);
	protocol_layout(gen_buffer);
	// source host
	strcpy(gen_buffer, buf[3]);
	sourceip_layout(gen_buffer);
	// destination host
	strcpy(gen_buffer, buf[8]);
	destip_layout(gen_buffer);
	//port_layout
	strcpy(src_port, buf[5]);
	strcpy(dst_port, buf[6]);
	port_layout(src_port, dst_port);
	// connection status
	printf("%-10s", buf[7]);
	// EOL
	printf("\n");	    
	}    
    }



// NATed icmp protocol
int protocol_icmp_unr(char *line) {
    char protocol[6]="";
    char src_ip[25]="", dst_ip[25]="";
    char ip_buffer[15]="", gen_buffer[25]="", port_buffer[5]=""; 
    char ports[15]="";
    char *token;
    char *split;
    char *buf[30];
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
        }
    else {
        buf[3]="";
        buf[4]="";
        buf[9]="";
        buf[10]="";
        }
    
    if ((!strcmp(buf[3],buf[10])==0) && (strcmp(buf[4],buf[9])==0)) {	
        // protocol
        strcpy(gen_buffer, buf[0]);
        protocol_layout(gen_buffer);
        // source host
        strcpy(gen_buffer, buf[3]);
        sourceip_layout(gen_buffer);
        // destination host
        strcpy(gen_buffer, buf[4]);
        destip_layout(gen_buffer);
        // port layout
        printf("%-13s"," ");
        // connection status
        printf("%-10s", buf[8]);
        // EOL
        printf("\n");	    
        }    
    }

int protocol_icmp_rep(char *line) {
    char protocol[6]="";
    char src_ip[25]="", dst_ip[25]="";
    char ip_buffer[15]="", gen_buffer[25]="", port_buffer[5]=""; 
    char ports[15]="";
    char *token;
    char *split;
    char *buf[30];
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
	}
    else {
	buf[3]="";
	buf[4]="";
	buf[8]="";
	buf[9]="";
	}
	
    if ((!strcmp(buf[3],buf[9])==0) && (strcmp(buf[4],buf[8])==0)) {	
	// protocol
	strcpy(gen_buffer, buf[0]);
	protocol_layout(gen_buffer);
	// source host
	strcpy(gen_buffer, buf[3]);
	sourceip_layout(gen_buffer);
	// destination host
	strcpy(gen_buffer, buf[4]);
	destip_layout(gen_buffer);
	// port layout
	printf("%-13s"," ");
	// connection status
	printf("%-10s", "[REPLIED]");
	// EOL
	printf("\n");	    
	}
    }
// -- End of NATed protocols

// -- Internal used functions
int extract_ip(char *gen_buffer) {
    char *split;
    split = strtok(gen_buffer,"=");
    split = strtok(NULL,"=");
    strcpy(gen_buffer,split);
    }

int protocol_layout(char *gen_buffer) {
    char protocol[6]="";
    memcpy(protocol, gen_buffer, 5);
    printf("%-6s", protocol);
    }


int sourceip_layout(char *gen_buffer) {
    char src_ip[30]="";
    if (RESOLVE) {
        lookup_hostname(gen_buffer);}
    memcpy(src_ip, gen_buffer, 24);
    printf("%-25s", src_ip);
    }


int destip_layout(char *gen_buffer) {
    char dst_ip[30]="";
    if (RESOLVE) {
        lookup_hostname(gen_buffer);}
    memcpy(dst_ip, gen_buffer, 24);
    printf("%-25s", dst_ip);
    }

    
int port_layout(char *src_port, char *dst_port) {
    char ports[12]="";
    char *split;
    // source port
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
    printf("%-13s", ports);
    }    


int lookup_hostname(char *r_host) {
    u_int addr;
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


int match(char *string, char *pattern) {
    int i;
    regex_t re;
    char buf[200];
    i=regcomp(&re, pattern, REG_EXTENDED|REG_NOSUB);
    if (i != 0) {
	(void)regerror(i,&re,buf,sizeof buf);
	//printf("%s\n",buf);
	return(0);                       /* report error */
	}
    i = regexec(&re, string, (size_t) 0, NULL, 0);
    regfree(&re);
    if (i != 0) {
	(void)regerror(i,&re,buf,sizeof buf);
	//printf("%s\n",buf);
	return(0);                       /* report error */
	}
    return(1);
    }
// -- End of internal used functions

// -- The End --
