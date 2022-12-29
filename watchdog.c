#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include "ping_func.h"

int main() {
    struct sockaddr_in wdAddress, pingAddress;

    socklen_t pingAddressLen;

    char SignalOK = '\0';
    
    int socketfd = INVALID_SOCKET, pingSocket = INVALID_SOCKET;

    int timer = 0, bytes_received = 0;

    printf("[WATCHDOG] Watchdog started.\n");

    socketfd = setupTCPSocket(&wdAddress);

    memset(&pingAddress, 0, sizeof(pingAddress));

    pingAddressLen = sizeof(pingAddress);

    pingSocket = accept(socketfd, (struct sockaddr *) &pingAddress, &pingAddressLen);

    if (pingSocket == -1)
    {
        perror("accept");
        exit(1);
    }

    printf("[WATCHDOG] Ping connected\n");

    while (timer < WATCHDOG_TIMEOUT)
    {
        bytes_received = recv(pingSocket, &SignalOK, sizeof(char), MSG_DONTWAIT);

        if (bytes_received > 0)
        {
            timer = 0;
            continue;
        }

        if (errno == EWOULDBLOCK)
        {
            struct pollfd p = { pingSocket, POLLIN, 0 };
            int r = poll(&p, 1, 1000);

            if (r == 1)
                continue;

            if (r == 0)
                timer++;
        }
    }
    
    if (timer == WATCHDOG_TIMEOUT)
    {
        fprintf(stderr, "[WATCHDOG] Timeout\n");
        exit(1);
    }

    close(pingSocket);
    close(socketfd);

    return 0;
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
        exit(1);
    }

    if (setsockopt(socketfd, SOL_SOCKET, SO_REUSEADDR, &canReused, sizeof(canReused)) == -1)
    {
        perror("setsockopt");
        exit(1);
    }

    if (bind(socketfd, (struct sockaddr *)socketAddress, sizeof(*socketAddress)) == -1)
    {
        perror("bind");
        exit(1);
    }

    if (listen(socketfd, 1) == -1)
    {
        perror("listen");
        exit(1);
    }

    printf("[WATCHDOG] Socket successfully created.\n");

    return socketfd;
}

ssize_t sendDataTCP(int socketfd, void* buffer, int len) {
    ssize_t sentd = send(socketfd, buffer, len, 0);

    if (sentd == -1)
    {
        perror("send");
        exit(1);
    }

    return sentd;
}

ssize_t receiveDataTCP(int socketfd, void *buffer, int len) {
    ssize_t recvb = recv(socketfd, buffer, len, 0);

    if (recvb == -1)
    {
        perror("recv");
        exit(1);
    }

    return recvb;
}
