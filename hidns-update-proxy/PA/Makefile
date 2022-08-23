appname = pa_server
mainobj = pa_server.o
objects = eventcontext.o ins_verifyasync.o prefixtrie.o updatemsgfmt.o updatemsgtools.o verifystruct.o workqueue.o
all: $(appname)

$(appname): $(mainobj) $(objects)
	gcc -o $@ $(mainobj) $(objects) -lssl -lcrypto -lpthread -lins-resolv

$(mainobj): pa_server.c
	gcc -c -o $@ pa_server.c

eventcontext.o: eventcontext.c
	gcc -c -o $@ eventcontext.c

ins_verifyasync.o: ins_verifyasync.c
	gcc -c -o $@ ins_verifyasync.c

updatemsgfmt.o: updatemsgfmt.c
	gcc -c -o $@ updatemsgfmt.c

updatemsgtools.o: updatemsgtools.c
	gcc -c -o $@ updatemsgtools.c

verifystruct.o: verifystruct.c
	gcc -c -o $@ verifystruct.c

prefixtrie.o: prefixtrie.c
	gcc -c -o $@ prefixtrie.c

workqueue.o: workqueue.c
	gcc -c -o $@ workqueue.c

clean:
	rm -rf *.o pa_server
.PHONY: clean
