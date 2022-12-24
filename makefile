CC = gcc
CFLAGS = -Wall -g

.PHONY: all clean

all: ping better_ping watchdog

ping: ping.o
	$(CC) $(CFLAGS) $< -o parta

better_ping: betterr_ping.o
	$(CC) $(CFLAGS) $< -o partb

watchdog: watchdog.o
	$(CC) $(CFLAGS) watchdog.c -o watchdog

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o parta watchdog partb
