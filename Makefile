#-------------------------------------------------------------------------------
#
# $Id: Makefile,v 1.2 2002/08/03 20:46:40 mardan Exp $ 
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


SHELL = /bin/sh
BINDIR = /usr/bin
ETCDIR = /etc
MANDIR = /usr/share/man/man1
INSTALL = install -c


CC = gcc -O2


PROG_SRC = netstat-nat.c
PROG_BIN = netstat-nat
PROG_MAN = netstat-nat.1

all:	clean netstat-nat


netstat-nat:
	$(CC) -o $(PROG_BIN) $(PROG_SRC) 


clean:	
	rm -f *.o $(PROG_BIN)


install:
	$(INSTALL) -s $(PROG_BIN) $(BINDIR)
	$(INSTALL) -m 444 $(PROG_MAN) $(MANDIR)
