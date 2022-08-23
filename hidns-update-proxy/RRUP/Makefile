appname = prproxy
headers = iPrefixRegisterProxyConfig.h ipsock.h nipsock.h updatemsgfmt.h updatemsgtools.h verifystruct.h ins_verifysync.h
objects = prproxy.o ipsock.o nipsock.o updatemsgfmt.o updatemsgtools.o verifystruct.o ins_verifysync.o
all: $(appname)

$(appname): $(objects)
	gcc -o $@ $(objects) -lssl -lcrypto -lpthread -lins-resolv

prproxy.o: prproxy.c
	gcc -c -o $@ prproxy.c

ipsock.o: ipsock.c
	gcc -c -o $@ ipsock.c

nipsock.o: nipsock.c
	gcc -c -o $@ nipsock.c

updatemsgfmt.o: updatemsgfmt.c
	gcc -c -o $@ updatemsgfmt.c

updatemsgtools.o: updatemsgtools.c
	gcc -c -o $@ updatemsgtools.c

verifystruct.o: verifystruct.c
	gcc -c -o $@ verifystruct.c

ins_verifysync.o: ins_verifysync.c
	gcc -c -o $@ ins_verifysync.c

clean:
	rm -rf *.o prproxy
.PHONY: clean
