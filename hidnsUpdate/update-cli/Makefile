clientapp = update-cli
secclient = update-sslcli

COMMONDIR = ../../hidnsCommon
clientappobj = $(clientapp).o
secclientobj = $(secclient).o
objects = syncverify.o updatemsgfmt.o updatemsgtools.o verifystruct.o base64.o resolvmsgfmt.o 
all: $(clientapp) $(secclient)

$(secclient): $(secclientobj) $(objects)
	gcc -o $@ $^ -lssl -lcrypto -lhiredis -I$(COMMONDIR)

$(clientapp): $(clientappobj) $(objects)
	gcc -o $@ $^ -lssl -lcrypto -lhiredis -I$(COMMONDIR)

$(secclientobj): update-sslcli.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

$(clientappobj): update-cli.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

syncverify.o: $(COMMONDIR)/syncverify.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

updatemsgfmt.o: $(COMMONDIR)/updatemsgfmt.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

updatemsgtools.o: $(COMMONDIR)/updatemsgtools.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

verifystruct.o: $(COMMONDIR)/verifystruct.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

base64.o: $(COMMONDIR)/base64.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

resolvmsgfmt.o: $(COMMONDIR)/resolvmsgfmt.c
	gcc -c -o $@ $^ -I$(COMMONDIR)


clean:
	rm -rf *.o $(clientapp) $(secclient)
.PHONY: clean
