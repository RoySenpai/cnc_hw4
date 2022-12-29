#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include "ping_func.h"

int main() {
    struct sockaddr_in wdAddress, pingAddress;

    struct pollfd fd;

    socklen_t pingAddressLen;

    char SignalOK = '\0';
    
    int socketfd = INVALID_SOCKET, pingSocket = INVALID_SOCKET, timer = 0, bytes_received = 0, res;

    socketfd = setupTCPSocket(&wdAddress);

    memset(&pingAddress, 0, sizeof(pingAddress));

    pingAddressLen = sizeof(pingAddress);

    fd.fd = socketfd;
    fd.events = POLLIN;
    res = poll(&fd, 1, PING_MS);

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
        kill(getppid(), SIGKILL);
        perror("accept");
        exit(EXIT_FAILURE);
    }

    while (timer < WATCHDOG_TIMEOUT)
    {
        bytes_received = receiveDataTCP(pingSocket, &SignalOK, sizeof(char));

        if (bytes_received > 0)
        {
            timer = 0;
            continue;
        }

        if (bytes_received == -1)
        {
            sleep(1);
            timer++;
        }
    }
    
    kill(getppid(), SIGUSR1);

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
        kill(getppid(), SIGKILL);
        perror("socket");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &canReused, sizeof(canReused)) == -1)
    {
        kill(getppid(), SIGKILL);
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    if (bind(socketfd, (struct sockaddr *)socketAddress, sizeof(*socketAddress)) == -1)
    {
        kill(getppid(), SIGKILL);
        perror("bind");
        exit(EXIT_FAILURE);
    }

    if (listen(socketfd, 1) == -1)
    {
        kill(getppid(), SIGKILL);
        perror("listen");
        exit(EXIT_FAILURE);
    }

    return socketfd;
}

ssize_t receiveDataTCP(int socketfd, void *buffer, int len) {
    ssize_t recvb = recv(socketfd, buffer, len, MSG_DONTWAIT);

    if (recvb == -1)
    {
        if (errno != EWOULDBLOCK)
        {
            kill(getppid(), SIGKILL);
            perror("recv");
            exit(EXIT_FAILURE);
        }

        else
            return -1;
    }

    return recvb;
}
