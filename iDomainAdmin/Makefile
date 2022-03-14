all: idomainadmin pttest updatetest aoftest manager
	rm -f *.o
server = idnsadmin.o
prefixtree = pttest.o
rrup = updatetest.o
aof = aoftest.o
objects = ipsock.o idns_pt.o idns_eit.o command.o security.o updatezone.o idns_aof.o
cc = gcc
idomainadmin: $(server) $(objects)
	$(cc) -o $@ $^ -lpthread

pttest: $(prefixtree) $(objects)
	$(cc) -o $@ $^ -lpthread

updatetest: $(rrup) $(objects)
	$(cc) -o $@ $^ -lpthread

aoftest: $(aof) $(objects)
	$(cc) -o $@ $^ -lpthread

manager: manager.o ipsock.o

idnsadmin.o: globalconfig.h iDomainAdminConfig.h
	$(cc) -c idnsadmin.c
ipsock.o:
idns_pt.o: 
idns_eit.o: idnsadmin.h
	$(cc) -c idns_eit.c
command.o: 
security.o:
updatezone.o: iDomainAdminConfig.h
idns_aof.o:

clean:
	rm -f *.o idomainadmin pttest updatetest aoftest manager
.PHONY: clean
