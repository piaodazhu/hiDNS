LIBNAME = libhidns.so
LIBDIR = /usr/local/lib/
HDRDIR = /usr/local/include/
HDRNAME = hidns/

COMMONDIR = ../hidnsCommon
headers = hresolv.h $(wildcard $(COMMONDIR)/*.h)
srcfile = hresolv.c $(wildcard $(COMMONDIR)/*.c)
objects = hresolv.o $(patsubst $(COMMONDIR)/%.c, %.o, $(wildcard $(COMMONDIR)/*.c))

all: $(LIBNAME)
install: all
	mkdir -p $(HDRDIR)$(HDRNAME)
	cp $(LIBNAME) $(LIBDIR)
	cp $(headers) $(HDRDIR)$(HDRNAME)
	ldconfig
	rm -rf *.o *.so*
	echo "Installing done."

uninstall:
	rm -rf $(LIBDIR)$(LIBNAME)
	rm -rf $(HDRDIR)$(HDRNAME)
	ldconfig
	echo "Uninstalling done."

$(LIBNAME): $(objects)
	gcc -shared -o $@ $(objects) -I$(COMMONDIR) -lpthread -lcrypto

%.o : %.c
	$(CC) -c -o $@ -fPIC $^ -I$(COMMONDIR)

$(patsubst $(COMMONDIR)/%.c, %.o, $(wildcard $(COMMONDIR)/*.c)): $(srcfile)
	gcc -c -o $@ -fPIC $(COMMONDIR)/$*.c -I$(COMMONDIR)

clean:
	rm -rf *.o *.so*
.PHONY: clean
