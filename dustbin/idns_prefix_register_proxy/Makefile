objects = iprproxy.o ipsock.o nipsock.o command.o
cc = gcc
proxy: $(objects)
	$(cc) -o $@ $^ -lpthread
	rm -f *.o

iprproxy.o: globalconfig.h iPrefixRegisterProxyConfig.h

clean:
	rm -f *.o proxy
.PHONY: clean