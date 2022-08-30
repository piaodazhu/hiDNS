CC = gcc

TOPDIR := $(shell pwd)
SRCDIR := $(TOPDIR)/src
OBJDIR := $(TOPDIR)/obj
BINDIR := $(TOPDIR)/bin
INCDIR := $(shell pwd)/../hidnsCommon
BIN := main

SUBDIR :=  src obj
OBJLINK := --std=c99
CMPFLAG := 

LOGMOD := INSSLOG_SYSLOG
export CC TOPDIR OBJDIR BINDIR INCDIR BIN OBJLINK LOGMOD OPTFLAG

all: CHECKDIR $(SUBDIR)
CHECKDIR:
	mkdir -p $(SUBDIR) $(BINDIR)
$(SUBDIR): RUN
	make -C $@
	echo "Successfully build. hidns-ns is under $(BINDIR)"
RUN:

install: all
	cp $(BINDIR)/hidns-ns /usr/bin/
	mkdir -p /etc/hidns-ns/
	cp $(TOPDIR)/config.json /etc/hidns-ns/config.json
	cp $(TOPDIR)/systemd/hidns-ns.service /etc/systemd/system/
	echo "Successfully installed hidns-ns. Default configuration: /etc/hidns-ns/config.json"

uninstall: 
	rm -rf /usr/bin/hidns-ns
	rm -rf /etc/hidns-ns
	rm -rf /etc/systemd/system/hidns-ns.service
	echo "Successfully uninstalled hidns-ns."

clean:
	rm -rf $(OBJDIR)/*.o $(BINDIR) 
.PHONY: clean