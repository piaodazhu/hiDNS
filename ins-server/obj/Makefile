modules = ins_local_module.o ins_remote_module.o dns_module.o hidns_events.o events.o
objects = rkt.o loadconf.o ipsock.o ins_msgformat.o dns_utils.o ins_prefix.o ins_cache.o base64.o verifystruct.o ins_verifysync.o
resolver = ins_resolv.o ipsock.o ins_msgformat.o ins_cache.o
pathtest = pathtest.o
servertest = servertest.o
clienttest = clienttest.o
ins-server = ins-server.o

hidns_loadbalancer = hidns_loadbalancer.o

cjson = cJSON.o

all: server test

server: $(BINDIR)/ins-server $(BINDIR)/hidns_loadbalancer
test: $(BINDIR)/pathtest $(BINDIR)/servertest

$(BINDIR)/ins-server: $(ins-server) $(modules) $(objects) $(cjson)
	gcc -o $@ $^ -lresolv -lpthread -lhiredis

$(BINDIR)/pathtest: $(pathtest) $(modules) $(objects) $(cjson) 
	gcc -o $@ $^ -lresolv -lhiredis

$(BINDIR)/servertest: $(servertest) $(modules) $(objects) $(cjson)
	gcc -o $@ $^ -lresolv -lhiredis

$(BINDIR)/hidns_loadbalancer: $(hidns_loadbalancer) $(modules) $(objects) $(cjson)
	gcc -o $@ $^ -lresolv -lpthread -lhiredis

clean:
	rm -f *.o cJSON/*.gch pathtest servertest clienttest ins-server ins-client hidns_loadbalancer

.PHONY: clean