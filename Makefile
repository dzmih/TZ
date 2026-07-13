CC = cc
CFLAGS = -Wall -Wextra -Wpedantic -std=c11 -Iinclude $(shell pkg-config --cflags glib-2.0 libpcap)
LDLIBS = $(shell pkg-config --libs glib-2.0 libpcap)

all: netstatd netstatctl

netstatd: src/daemon.o src/stats.o src/sniff.o
	$(CC) $(CFLAGS) -o netstatd src/daemon.o src/stats.o src/sniff.o $(LDLIBS)

netstatctl: src/cli.o
	$(CC) $(CFLAGS) -o netstatctl src/cli.o

src/daemon.o: src/daemon.c
	$(CC) $(CFLAGS) -c src/daemon.c -o src/daemon.o

src/cli.o: src/cli.c
	$(CC) $(CFLAGS) -c src/cli.c -o src/cli.o

src/stats.o: src/stats.c
	$(CC) $(CFLAGS) -c src/stats.c -o src/stats.o

src/sniff.o: src/sniff.c
	$(CC) $(CFLAGS) -c src/sniff.c -o src/sniff.o

clean:
	rm -f src/*.o netstatd netstatctl stats.o
