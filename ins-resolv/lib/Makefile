libname = libins-resolv.so
headers = ins_msgformat.h ins_prefix.h ins_resolv.h ins_localcache.h ins_ipsock.h
objects = ins_msgformat.o ins_prefix.o ins_resolv.o ins_localcache.o ins_ipsock.o
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
	gcc -shared -o $@ $(objects) -lhiredis

ins_msgformat.o:
	gcc -c -o $@ -fPIC ins_msgformat.c

ins_prefix.o:
	gcc -c -o $@ -fPIC ins_prefix.c

ins_resolv.o:
	gcc -c -o $@ -fPIC ins_resolv.c

ins_localcache.o:
	gcc -c -o $@ -fPIC ins_localcache.c

ins_ipsock.o:
	gcc -c -o $@ -fPIC ins_ipsock.c

clean:
	rm -rf *.o *.so
.PHONY: clean
