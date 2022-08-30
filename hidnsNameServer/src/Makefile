all:	$(OBJDIR)/localproc_module.o $(OBJDIR)/forwarder_module.o \
	$(OBJDIR)/dns_module.o $(OBJDIR)/dns_utils.o \
	$(OBJDIR)/loadconf.o $(OBJDIR)/rkt.o $(OBJDIR)/ipsock.o \
	$(OBJDIR)/prefixtools.o $(OBJDIR)/resolvmsgfmt.o \
	$(OBJDIR)/cJSON.o $(OBJDIR)/hidns-ns.o \
	$(OBJDIR)/eventsys.o $(OBJDIR)/hidns_events.o \
	$(OBJDIR)/base64.o $(OBJDIR)/verifystruct.o $(OBJDIR)/syncverify.o \
	$(OBJDIR)/peccache.o $(OBJDIR)/hashmap.o $(OBJDIR)/timewheel.o $(OBJDIR)/ttlmap.o 


$(OBJDIR)/hidns-ns.o: hidns-ns.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/localproc_module.o: localproc_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/forwarder_module.o: forwarder_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/dns_module.o: dns_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/dns_utils.o: dns_utils.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/loadconf.o: loadconf.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/rkt.o: rkt.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/eventsys.o: eventsys.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/hidns_events.o: hidns_events.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG) -I$(INCDIR)

# ------------------------ COMMON ----------------------------

$(OBJDIR)/ipsock.o: $(INCDIR)/ipsock.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/prefixtools.o: $(INCDIR)/prefixtools.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/resolvmsgfmt.o: $(INCDIR)/resolvmsgfmt.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/cJSON.o: $(INCDIR)/cJSON.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/base64.o: $(INCDIR)/base64.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/verifystruct.o: $(INCDIR)/verifystruct.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/syncverify.o: $(INCDIR)/syncverify.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/peccache.o: $(INCDIR)/peccache.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/hashmap.o: $(INCDIR)/hashmap.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/timewheel.o: $(INCDIR)/timewheel.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

$(OBJDIR)/ttlmap.o: $(INCDIR)/ttlmap.c
	$(CC) -c $^ -o $@ $(CMPFLAG) -I$(INCDIR)

