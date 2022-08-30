all:	$(OBJDIR)/ins_local_module.o $(OBJDIR)/ins_remote_module.o \
	$(OBJDIR)/dns_module.o $(OBJDIR)/dns_utils.o $(OBJDIR)/pathtest.o \
	$(OBJDIR)/loadconf.o $(OBJDIR)/rkt.o $(OBJDIR)/ipsock.o \
	$(OBJDIR)/ins_prefix.o $(OBJDIR)/ins_msgformat.o $(OBJDIR)/ins_resolv.o \
	$(OBJDIR)/cJSON.o $(OBJDIR)/ins-server.o $(OBJDIR)/servertest.o \
	$(OBJDIR)/ins-client.o $(OBJDIR)/clienttest.o $(OBJDIR)/ins_cache.o \
	$(OBJDIR)/events.o $(OBJDIR)/hidns_events.o $(OBJDIR)/hidns_loadbalancer.o \
	$(OBJDIR)/base64.o $(OBJDIR)/verifystruct.o $(OBJDIR)/ins_verifysync.o \
	$(OBJDIR)/hidns_cache.o $(OBJDIR)/hashmap.o $(OBJDIR)/timewheel.o $(OBJDIR)/ttlmap.o 


$(OBJDIR)/ins_local_module.o: ins_local_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG)
$(OBJDIR)/ins_remote_module.o: ins_remote_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG)
$(OBJDIR)/dns_module.o: dns_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG)
$(OBJDIR)/dns_utils.o: dns_utils.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/pathtest.o: pathtest.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/loadconf.o: loadconf.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG)
$(OBJDIR)/rkt.o: rkt.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ipsock.o: ipsock.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ins_prefix.o: ins_prefix.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ins_msgformat.o: ins_msgformat.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ins_resolv.o: ins_resolv.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/cJSON.o: $(TOPDIR)/cJSON/cJSON.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ins-server.o: main.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG)
$(OBJDIR)/servertest.o: servertest.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ins-client.o: ins-client.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/clienttest.o: clienttest.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ins_cache.o: ins_cache.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/events.o: events.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG)
$(OBJDIR)/hidns_events.o: hidns_events.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG)
$(OBJDIR)/hidns_loadbalancer.o: hidns_loadbalancer.c
	$(CC) -c $^ -o $@ -D $(LOGMOD) $(CMPFLAG)
$(OBJDIR)/base64.o: base64.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/verifystruct.o: verifystruct.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ins_verifysync.o: ins_verifysync.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/hidns_cache.o: hidns_cache.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/hashmap.o: hashmap.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/timewheel.o: timewheel.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
$(OBJDIR)/ttlmap.o: ttlmap.c
	$(CC) -c $^ -o $@ $(CMPFLAG)
