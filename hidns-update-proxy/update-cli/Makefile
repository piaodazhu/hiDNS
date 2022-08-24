clientapp = update-cli
secclient = update-sslcli
clientappobj = $(clientapp).o
secclientobj = $(secclient).o
objects = ins_verifysync.o updatemsgfmt.o updatemsgtools.o verifystruct.o
all: $(clientapp) $(secclient)

$(secclient): $(secclientobj) $(objects)
	gcc -o $@ $^ -lssl -lcrypto -lins-resolv

$(clientapp): $(clientappobj) $(objects)
	gcc -o $@ $^ -lssl -lcrypto -lins-resolv

$(secclientobj): update-sslcli.c
	gcc -c -o $@ $^

$(clientappobj): update-cli.c
	gcc -c -o $@ $^

ins_verifysync.o: ins_verifysync.c
	gcc -c -o $@ $^

updatemsgfmt.o: updatemsgfmt.c
	gcc -c -o $@ $^

updatemsgtools.o: updatemsgtools.c
	gcc -c -o $@ $^

verifystruct.o: verifystruct.c
	gcc -c -o $@ $^


clean:
	rm -rf *.o $(clientapp) $(secclient)
.PHONY: clean
