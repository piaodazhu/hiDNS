CC = gcc

TOPDIR := $(shell pwd)
SRCDIR := $(TOPDIR)/src
OBJDIR := $(TOPDIR)/obj
BINDIR := $(TOPDIR)/bin
BIN := main

SUBDIR :=  src obj
OBJLINK := --std=c99
CMPFLAG := 

LOGMOD := INSSLOG_SYSLOG
export CC TOPDIR OBJDIR BINDIR BIN OBJLINK LOGMOD OPTFLAG

all: CHECKDIR $(SUBDIR)
CHECKDIR:
	mkdir -p $(SUBDIR) $(BINDIR)
$(SUBDIR): RUN
	make -C $@
	echo "Successfully build. ins-server is under $(BINDIR)"
RUN:

install: all
	cp $(BINDIR)/ins-server /usr/bin/
	mkdir -p /etc/ins-server/
	cp $(TOPDIR)/config.json /etc/ins-server/config.json
	cp $(TOPDIR)/systemd/ins-server.service /etc/systemd/system/
	echo "Successfully installed ins-server. Default configuration: /etc/ins-server/config.json"

uninstall: 
	rm -rf /usr/bin/ins-server
	rm -rf /etc/ins-server
	rm -rf /etc/systemd/system/ins-server.service
	echo "Successfully uninstalled ins-server."

clean:
	rm -rf $(OBJDIR)/*.o $(BINDIR) 
.PHONY: clean