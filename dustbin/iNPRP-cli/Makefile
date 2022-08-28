cc=gcc
client: inprp-cli.o command.o nipsock.o
	$(cc) -o $@ $^
	rm *.o

clean:
	rm -f *.o client
.PHONY: clean