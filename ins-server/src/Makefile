all:	$(OBJDIR)/ins_local_module.o $(OBJDIR)/ins_remote_module.o \
	$(OBJDIR)/dns_module.o $(OBJDIR)/dns_utils.o $(OBJDIR)/pathtest.o \
	$(OBJDIR)/loadconf.o $(OBJDIR)/rkt.o $(OBJDIR)/ipsock.o \
	$(OBJDIR)/ins_prefix.o $(OBJDIR)/ins_msgformat.o $(OBJDIR)/ins_resolv.o \
	$(OBJDIR)/cJSON.o $(OBJDIR)/ins-server.o $(OBJDIR)/servertest.o \
	$(OBJDIR)/ins-client.o $(OBJDIR)/clienttest.o $(OBJDIR)/ins_cache.o \
	$(OBJDIR)/events.o $(OBJDIR)/hidns_events.o $(OBJDIR)/hidns_loadbalancer.o \
	$(OBJDIR)/base64.o $(OBJDIR)/verifystruct.o $(OBJDIR)/ins_verifysync.o

$(OBJDIR)/ins_local_module.o: ins_local_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD)
$(OBJDIR)/ins_remote_module.o: ins_remote_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD)
$(OBJDIR)/dns_module.o: dns_module.c
	$(CC) -c $^ -o $@ -D $(LOGMOD)
$(OBJDIR)/dns_utils.o: dns_utils.c
	$(CC) -c $^ -o $@
$(OBJDIR)/pathtest.o: pathtest.c
	$(CC) -c $^ -o $@
$(OBJDIR)/loadconf.o: loadconf.c
	$(CC) -c $^ -o $@ -D $(LOGMOD)
$(OBJDIR)/rkt.o: rkt.c
	$(CC) -c $^ -o $@
$(OBJDIR)/ipsock.o: ipsock.c
	$(CC) -c $^ -o $@
$(OBJDIR)/ins_prefix.o: ins_prefix.c
	$(CC) -c $^ -o $@
$(OBJDIR)/ins_msgformat.o: ins_msgformat.c
	$(CC) -c $^ -o $@
$(OBJDIR)/ins_resolv.o: ins_resolv.c
	$(CC) -c $^ -o $@
$(OBJDIR)/cJSON.o: $(TOPDIR)/cJSON/cJSON.c
	$(CC) -c $^ -o $@
$(OBJDIR)/ins-server.o: main.c
	$(CC) -c $^ -o $@ -D $(LOGMOD)
$(OBJDIR)/servertest.o: servertest.c
	$(CC) -c $^ -o $@
$(OBJDIR)/ins-client.o: ins-client.c
	$(CC) -c $^ -o $@
$(OBJDIR)/clienttest.o: clienttest.c
	$(CC) -c $^ -o $@
$(OBJDIR)/ins_cache.o: ins_cache.c
	$(CC) -c $^ -o $@
$(OBJDIR)/events.o: events.c
	$(CC) -c $^ -o $@ -D $(LOGMOD)
$(OBJDIR)/hidns_events.o: hidns_events.c
	$(CC) -c $^ -o $@ -D $(LOGMOD)
$(OBJDIR)/hidns_loadbalancer.o: hidns_loadbalancer.c
	$(CC) -c $^ -o $@ -D $(LOGMOD)
$(OBJDIR)/base64.o: base64.c
	$(CC) -c $^ -o $@
$(OBJDIR)/verifystruct.o: verifystruct.c
	$(CC) -c $^ -o $@
$(OBJDIR)/ins_verifysync.o: ins_verifysync.c
	$(CC) -c $^ -o $@
