appname = prproxy
headers = iPrefixRegisterProxyConfig.h ipsock.h nipsock.h updatemsgfmt.h updatemsgtools.h verifystruct.h ins_verifysync.h
objects = prproxy.o ipsock.o nipsock.o updatemsgfmt.o updatemsgtools.o verifystruct.o ins_verifysync.o
all: $(appname)

$(appname): $(objects)
	gcc -o $@ $(objects) -lssl -lcrypto -lpthread

prproxy.o:
	gcc -c -o $@ prproxy.c

ipsock.o:
	gcc -c -o $@ ipsock.c

nipsock.o:
	gcc -c -o $@ nipsock.c

updatemsgfmt.o:
	gcc -c -o $@ updatemsgfmt.c

updatemsgtools.o:
	gcc -c -o $@ updatemsgtools.c

verifystruct.o:
	gcc -c -o $@ verifystruct.c

ins_verifysync.o:
	gcc -c -o $@ ins_verifysync.c

clean:
	rm -rf *.o prproxy
.PHONY: clean
