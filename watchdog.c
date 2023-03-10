/*
 *  Communication and Computing Course Assigment 4:
 *  RAW Sockets and ICMP Protocol
 *  Copyright (C) 2022-2023  Roy Simanovich and Yuval Yurzdichinsky
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "ping_func.h"

int main() {
    // Varibles setup
    struct sockaddr_in wdAddress, pingAddress;

    struct pollfd fd;

    socklen_t pingAddressLen;

    char SignalOK = '\0';
    
    int socketfd = INVALID_SOCKET, pingSocket = INVALID_SOCKET, timer = 0, bytes_received = 0, res;

    // Prepare the TCP socket with the ping program (default port 3000).
    socketfd = setupTCPSocket(&wdAddress);
    memset(&pingAddress, 0, sizeof(pingAddress));
    pingAddressLen = sizeof(pingAddress);

    // Accept the first connection request only.
    fd.fd = socketfd;
    fd.events = POLLIN;
    res = poll(&fd, 1, 1000);

    if (res == 0)
    {
        fprintf(stderr, "Watchdog internal error: please run better_ping.\n");
		exit(EXIT_FAILURE);
    }

    else if (res == -1)
    {
        perror("poll");
        exit(EXIT_FAILURE);
    }

    else
        pingSocket = accept(socketfd, (struct sockaddr *) &pingAddress, &pingAddressLen);

    if (pingSocket == -1)
    {
        perror("accept");
        exit(errno);
    }

    // Time functionality
    while (timer < WATCHDOG_TIMEOUT)
    {
        bytes_received = receiveTCPpacket(pingSocket, &SignalOK, sizeof(char));

        // Check if we received data
        if (bytes_received > 0)
        {
            // Error signal from the ping program - close EVERYTHING.
            if (SignalOK == '0')
            {
                close(pingSocket);
                close(socketfd);
                exit(EXIT_FAILURE);
            }

            timer = 0;
        }

        // We didn't receive a signal from the ping program, send a signal back and go to sleep for 1 second.
        else if (bytes_received == -1)
        {
            sendTCPpacket(pingSocket, &SignalOK, sizeof(char));
            timer++;
        }

        sleep(1);
    }

    SignalOK = '0';

    sendTCPpacket(pingSocket, &SignalOK, sizeof(char));
    
    close(pingSocket);
    close(socketfd);

    return EXIT_SUCCESS;
}

int setupTCPSocket(struct sockaddr_in *socketAddress) {
    int socketfd = INVALID_SOCKET, canReused = 1;

    memset(socketAddress, 0, sizeof(*socketAddress));

    socketAddress->sin_family = AF_INET;
    socketAddress->sin_addr.s_addr = INADDR_ANY;
    socketAddress->sin_port = htons(WATCHDOG_PORT);

    if ((socketfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        perror("socket");
        exit(errno);
    }

    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &canReused, sizeof(canReused)) == -1)
    {
        perror("setsockopt");
        exit(errno);
    }

    if (bind(socketfd, (struct sockaddr *)socketAddress, sizeof(*socketAddress)) == -1)
    {
        // Prevents from executing the program twice.
        if (errno == EADDRINUSE)
            fprintf(stderr, "Watchdog internal error: TCP Port %d is occupied.\nPlease check that you're not running better_ping twice.\n", WATCHDOG_PORT);

        else
            perror("bind");

        exit(errno);
    }

    if (listen(socketfd, 1) == -1)
    {
        perror("listen");
        exit(errno);
    }

    return socketfd;
}

ssize_t sendTCPpacket(int socketfd, void* buffer, int len) {
    ssize_t sentd = send(socketfd, buffer, len, MSG_DONTWAIT);

    if (sentd == -1)
    {
        perror("send");
        exit(errno);
    }

    return sentd;
}

ssize_t receiveTCPpacket(int socketfd, void *buffer, int len) {
    ssize_t recvb = recv(socketfd, buffer, len, MSG_DONTWAIT);

    if (recvb == -1)
    {
        // Non-Blocking I/O mode filter.
        if (errno != EWOULDBLOCK)
        {
            perror("recv");
            exit(errno);
        }
    }

    return recvb;
}
