appname = prproxy

COMMONDIR = ../../hidnsCommon
objects = prproxy.o ipsock.o nipsock.o updatemsgfmt.o updatemsgtools.o verifystruct.o syncverify.o base64.o resolvmsgfmt.o
all: $(appname)

$(appname): $(objects)
	gcc -o $@ $(objects) -lssl -lcrypto -lpthread -I$(COMMONDIR)

prproxy.o: prproxy.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

ipsock.o: $(COMMONDIR)/ipsock.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

nipsock.o: nipsock.c
	gcc -c -o $@ $^

updatemsgfmt.o: $(COMMONDIR)/updatemsgfmt.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

updatemsgtools.o: $(COMMONDIR)/updatemsgtools.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

verifystruct.o: $(COMMONDIR)/verifystruct.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

syncverify.o: $(COMMONDIR)/syncverify.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

base64.o: $(COMMONDIR)/base64.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

resolvmsgfmt.o: $(COMMONDIR)/resolvmsgfmt.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

clean:
	rm -rf *.o prproxy
.PHONY: clean
