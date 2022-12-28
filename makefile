CC = gcc
CFLAGS = -Wall -g

.PHONY: all clean

all: ping better_ping watchdog

ping: ping.o
	$(CC) $(CFLAGS) $< -o $@

better_ping: better_ping.o
	$(CC) $(CFLAGS) $< -o $@

watchdog: watchdog.o
	$(CC) $(CFLAGS) $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o ping better_ping watchdog
