#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
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

    printf("[WATCHDOG] Monitoring ping via TCP port %d.\n", WATCHDOG_PORT);

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
    
    if (timer == WATCHDOG_TIMEOUT)
    {
        fprintf(stderr, "[WATCHDOG] Timeout detected.\n");
        close(pingSocket);
        close(socketfd);
        exit(1);
    }

    printf("[WATCHDOG] Exit\n");

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

    printf("[WATCHDOG] TCP socket successfully created, waiting for connection...\n");

    return socketfd;
}

ssize_t receiveDataTCP(int socketfd, void *buffer, int len) {
    ssize_t recvb = recv(socketfd, buffer, len, MSG_DONTWAIT);

    if (recvb == -1)
    {
        if (errno != EWOULDBLOCK)
        {
            perror("recv");
            exit(1);
        }

        else
            return -1;
    }

    return recvb;
}
