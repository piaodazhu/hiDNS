libname = libins-resolv.so
headers = ins_msgformat.h ins_prefix.h ins_resolv.h ins_cache.h ins_ipsock.h ins_verifysync.h verifystruct.h base64.h
objects = ins_msgformat.o ins_prefix.o ins_resolv.o ins_cache.o ins_ipsock.o ins_verifysync.o verifystruct.o base64.o
all: $(libname)
install: all
	cp $(libname) /usr/local/lib/
	cp $(headers) /usr/local/include/
	ldconfig
	rm -rf *.o *.so
	echo "Installing done."

uninstall:
	rm -rf /usr/local/lib/$(libname)
	for header in $(headers); \
	do \
		rm -f "/usr/local/include/$${header}"; \
	done
	ldconfig
	echo "Uninstalling done."

$(libname): $(objects)
	gcc -shared -o $@ $(objects) -lhiredis -lpthread

ins_msgformat.o:
	gcc -c -o $@ -fPIC ins_msgformat.c

ins_prefix.o:
	gcc -c -o $@ -fPIC ins_prefix.c

ins_resolv.o:
	gcc -c -o $@ -fPIC ins_resolv.c

ins_cache.o:
	gcc -c -o $@ -fPIC ins_cache.c

ins_ipsock.o:
	gcc -c -o $@ -fPIC ins_ipsock.c

ins_verifysync.o:
	gcc -c -o $@ -fPIC ins_verifysync.c

verifystruct.o:
	gcc -c -o $@ -fPIC verifystruct.c

base64.o:
	gcc -c -o $@ -fPIC base64.c

clean:
	rm -rf *.o *.so
.PHONY: clean
