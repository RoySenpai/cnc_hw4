# Communication and Computing Course Assigment 4
### For Computer Science B.Sc. Ariel University

**By Roy Simanovich and Yuval Yurzdichinsky**

## Description
In this Ex we wrote a ping program, with two implementations:

* The first one (ping.c) is a simple ping program that generates 
a 32 bytes message and sends to a given IP address, waits for
a replay and prints information about the received packet.
This program can't handle timeouts and will get stuck until it'll
get a replay.

* The second one (better_ping.c) uses a watchdog implementation
(watchdog.c) to handle the timeouts. The ping program first connects
via TCP port 3000 to the watchdog and for every received packet, the
program sends an OK signal to the watchdog program, which resets it's
timer. Once the watchdog timer reaches 10 seconds mark, it will detect
it as a timeout and send a signal to the ping program to print a message
to the user and terminate itself.

# Requirements
* Linux machine
* GNU C Compiler
* Make

## Building
```
# Cloning the repo to local machine
git clone https://github.com/RoySenpai/cnc_hw4.git

# Building all the necessary files & the main programs
make all
```

## Running
* **NOTE:** Please notice that watchdog should never be run alone, as it depends on better_ping.
```
# Runs a ping program to a given ip address.
sudo ./ping <ipaddress>

# Runs a ping program with timeout, to a given ip address.
sudo ./better_ping <ipaddress>
```
