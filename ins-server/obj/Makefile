modules = ins_local_module.o ins_remote_module.o dns_module.o
objects = rkt.o loadconf.o ipsock.o ins_msgformat.o dns_utils.o ins_prefix.o ins_cache.o
resolver = ins_resolv.o ipsock.o ins_msgformat.o
pathtest = pathtest.o
servertest = servertest.o
clienttest = clienttest.o
ins-server = ins-server.o
ins-client = ins-client.o
cjson = cJSON.o

all: server test

server: $(BINDIR)/ins-server $(BINDIR)/ins-client
test: $(BINDIR)/pathtest $(BINDIR)/servertest $(BINDIR)/clienttest

$(BINDIR)/ins-server: $(ins-server) $(modules) $(objects) $(cjson)
	gcc -o $@ $^ -lresolv -lpthread -lhiredis

$(BINDIR)/pathtest: $(pathtest) $(modules) $(objects) $(cjson) 
	gcc -o $@ $^ -lresolv -lhiredis

$(BINDIR)/servertest: $(servertest) $(modules) $(objects) $(cjson)
	gcc -o $@ $^ -lresolv -lhiredis

$(BINDIR)/clienttest: $(clienttest) $(modules) $(objects) $(cjson)
	gcc -o $@ $^ -lresolv -lhiredis

$(BINDIR)/ins-client: $(ins-client) $(resolver)
	gcc -o $@ $^


clean:
	rm -f *.o cJSON/*.gch pathtest servertest clienttest ins-server ins-client

.PHONY: clean