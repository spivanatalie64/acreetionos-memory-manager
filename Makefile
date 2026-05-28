CFLAGS = -Wall -Wextra -O3 -fPIC -flto -I src
LDFLAGS = -shared -lpthread -ldl -flto

.PHONY: all clean install test

all: libacalloc.so hacrypt

libacalloc.so: src/acalloc.c src/acalloc.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

hacrypt: src/hacrypt.c src/acalloc.h libacalloc.so
	$(CC) $(CFLAGS) -o $@ $< -L. -lacalloc -lpthread -flto

test: libacalloc.so hacrypt
	$(CC) $(CFLAGS) -o test-leak src/test-leak.c -L. -lacalloc -lpthread
	$(CC) $(CFLAGS) -o test-stress src/test-stress.c -L. -lacalloc -lpthread
	LD_LIBRARY_PATH=. ./test-leak
	LD_LIBRARY_PATH=. ./test-stress

install: libacalloc.so hacrypt
	cp libacalloc.so /usr/local/lib/
	cp hacrypt /usr/local/bin/
	mkdir -p /usr/local/include/acreetionos
	cp src/acalloc.h /usr/local/include/acreetionos/

clean:
	rm -f libacalloc.so hacrypt test-leak test-stress src/*.o
