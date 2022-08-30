appname = pa_server

COMMONDIR = ../../hidnsCommon
mainobj = pa_server.o
objects = eventcontext.o asyncverify.o prefixtrie.o base64.o resolvmsgfmt.o updatemsgfmt.o updatemsgtools.o verifystruct.o workqueue.o
all: $(appname)

$(appname): $(mainobj) $(objects)
	gcc -o $@ $(mainobj) $(objects) -lssl -lcrypto -lpthread

$(mainobj): pa_server.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

eventcontext.o: eventcontext.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

asyncverify.o: $(COMMONDIR)/asyncverify.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

base64.o: $(COMMONDIR)/base64.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

resolvmsgfmt.o: $(COMMONDIR)/resolvmsgfmt.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

updatemsgfmt.o: $(COMMONDIR)/updatemsgfmt.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

updatemsgtools.o: $(COMMONDIR)/updatemsgtools.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

verifystruct.o: $(COMMONDIR)/verifystruct.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

prefixtrie.o: $(COMMONDIR)/prefixtrie.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

workqueue.o: workqueue.c
	gcc -c -o $@ $^ -I$(COMMONDIR)

clean:
	rm -rf *.o pa_server
.PHONY: clean
