#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <linux/watchdog.h>

#define INVALID_SOCKET -1

#define WATCHDOG_IP "127.0.0.1"
#define WATCHDOG_PORT 3000

int socketSetup(struct sockaddr_in *serverAddress);

int main() {
    struct sockaddr_in serverAddress, clientAddress;
    
    int socketfd = INVALID_SOCKET;

    printf("Watchdog started.\n");

    socketfd = socketSetup(&serverAddress);
    
    sleep(2);

    close(socketfd);

    return 0;
    /*printf("hello partb");
    while (timer < 10seconds)
    {
        recv();
        timer = 0seconds;
    }
    send("timeout")

    return 0;*/
}

int socketSetup(struct sockaddr_in *serverAddress) {
    int socketfd = INVALID_SOCKET, canReused = 1;

    memset(serverAddress, 0, sizeof(*serverAddress));
    serverAddress->sin_family = AF_INET;
    serverAddress->sin_addr.s_addr = INADDR_ANY;
    serverAddress->sin_port = htons(WATCHDOG_PORT);

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

    if (bind(socketfd, (struct sockaddr *)serverAddress, sizeof(*serverAddress)) == -1)
    {
        perror("bind");
        exit(1);
    }

    if (listen(socketfd, 1) == -1)
    {
        perror("listen");
        exit(1);
    }

    printf("Socket successfully created.\n");

    return socketfd;
}
