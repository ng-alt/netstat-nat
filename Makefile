#-------------------------------------------------------------------------------
#
# $Id: Makefile,v 1.5 2002/11/23 21:09:47 mardan Exp $ 
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

VERSION = 1.4.1
SHELL = /bin/sh
BINDIR = /usr/bin
ETCDIR = /etc
MANDIR = /usr/share/man/man1
DOCDIR = /usr/share/doc
INSTALL = install -c


CC = gcc -O2


PROG_SRC = netstat-nat.c
PROG_BIN = netstat-nat
PROG_MAN = netstat-nat.1
DOC = COPYING README INSTALL AUTHORS CHANGELOG

all:	netstat-nat


netstat-nat:
	$(CC) -o $(PROG_BIN) $(PROG_SRC) 


clean:	
	rm -f *.o $(PROG_BIN)


install:
	mkdir -p $(DOCDIR)/$(PROG_BIN)-$(VERSION) 
	mkdir -p $(MANDIR)
	$(INSTALL) -s $(PROG_BIN) $(BINDIR)
	$(INSTALL) -m 444 $(PROG_MAN) $(MANDIR)
	$(INSTALL) -m 444 $(DOC) $(DOCDIR)/$(PROG_BIN)-$(VERSION)


uninstall:
	rm -r $(BINDIR)/$(PROG_BIN)
	rm -r $(MANDIR)/$(PROG_MAN)
	rm -r $(DOCDIR)/$(PROG_BIN)*


