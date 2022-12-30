#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "ping_func.h"

int status, pid;

char destaddress[IP4_MAXLEN];

int main(int argc, char* argv[]) {
    // Varibles setup
    struct icmp icmphdr;
    struct iphdr *iphdr_res;
    struct icmphdr *icmphdr_res;
    struct sockaddr_in watchdogAddress, dest_in;
    struct timeval start, end;

    socklen_t addr_len;
    ssize_t bytes_received = 0;
    size_t datalen;

    int socketfd = INVALID_SOCKET, wdsocketfd = INVALID_SOCKET;

    double pingPongTime = 0.0;

    char *args[2];
    char packet[IP_MAXPACKET], response[IP_MAXPACKET], data[ICMP_ECHO_MSG_LEN], responseAddr[INET_ADDRSTRLEN];
    char OKSignal = '1';

    // Signal SIGUSR1 register to handler
    signal(SIGUSR1, sighandler);
    signal(SIGTERM, sighandler);

    // Prepare the data we're going to send.
    for (int i = 0; i < ICMP_ECHO_MSG_LEN - 1; ++i)
        data[i] = '1';

    data[ICMP_ECHO_MSG_LEN - 1] = '\0';
    datalen = (strlen(data) + 1);

    // Check the arguments passed to the program and check IP validity.
    checkArguments(argc, argv[1], &dest_in, &addr_len);

    strcpy(destaddress, argv[1]);

    // Prepare the RAW socket.
    socketfd = setupRawSocket(&icmphdr, getpid());

    // Prepare the TCP socket with the watchdog program (default port 3000).
    wdsocketfd = setupTCPSocket(&watchdogAddress);

    // Passing the arguments needed to start the watchdog program and fork the process.
    args[0] = "./watchdog";
    args[1] = NULL;

    pid = fork();

    // In child process (watchdog).
    if (pid == 0)
    {
        // Executing the watchdog program.
        execvp(args[0], args);

        // Incase of an error (shouldn't be any in normal operation).
        fprintf(stderr, "Error starting watchdog\n");
        perror("execvp");
        exit(errno);
    }

    // In parent process (better_ping).
    else
    {
        // Wait some time until the watchdog will prepare it's own TCP socket.
        usleep(WATCHDOG_WAITTIME);

        // Check if watchdog is still running
        if (waitpid(pid, &status, WNOHANG) != 0){
            exit(EXIT_FAILURE);
        }

        // Try to connect to the watchdog's socket.
        if (connect(wdsocketfd, (struct sockaddr*) &watchdogAddress, sizeof(watchdogAddress)) == -1)
        {
            kill(pid, SIGKILL);
            perror("connect");
            exit(EXIT_FAILURE);
        }

        printf("PING %s: %ld data bytes\n", argv[1], datalen);

        while(1)
        {
            // Prepare the ICMP ECHO packet.
            preparePing(packet, &icmphdr, data, datalen);

            // Calculate starting time.
            gettimeofday(&start, NULL);

            // Send the ICMP ECHO packet to the destination address.
            sendICMPpacket(socketfd, packet, datalen, &dest_in, sizeof(dest_in));

            // Wait and receive the ICMP ECHO REPLAY packet.
            bytes_received = receiveICMPpacket(socketfd, response, sizeof(response), &dest_in, &addr_len);

            // Calculate ending time.
            gettimeofday(&end, NULL);

            // Send OK signal to watchdog.
            sendTCPpacket(wdsocketfd, &OKSignal, sizeof(char));

            // Calculate the time it took to send and receive the packet
            pingPongTime = ((end.tv_sec - start.tv_sec) * PING_MS) + (((double)end.tv_usec - start.tv_usec) / PING_MS);

            // Extract the ICMP ECHO Replay headers via the IP header
            iphdr_res = (struct iphdr *)response;
            icmphdr_res = (struct icmphdr *)(response + iphdr_res->ihl*4);

            inet_ntop(AF_INET, &(iphdr_res->saddr), responseAddr, INET_ADDRSTRLEN);

            // Print the packet data (total length, source IP address, ICMP ECHO REPLAY sequance number, IP Time-To-Live and the calculated time).
            printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%0.3lf ms\n", 
            bytes_received, 
            responseAddr, 
            ntohs(icmphdr_res->un.echo.sequence),
            iphdr_res->ttl, 
            pingPongTime);

            // Make the ping program sleep some time before sending another ICMP ECHO packet.
            usleep(PING_WAIT_TIME);
        }

        close(socketfd);
    }

    wait(&status); // waiting for child to finish before exiting
    printf("child exit status is: %d\n", status);

    return 0;
}

void sighandler(int signum) {
    switch (signum)
    {
        case SIGTERM:
        {
            printf("Watchdog terminated process.\n");
            exit(EXIT_FAILURE);
            break;
        }

        case SIGUSR1:
        {
            printf("Server %s cannot be reached.\n", destaddress);
            exit(EXIT_SUCCESS);
            break;
        }
    
        default:
            break;
    }
}

int setupTCPSocket(struct sockaddr_in *socketAddress) {
    int socketfd = INVALID_SOCKET;

    memset(socketAddress, 0, sizeof(*socketAddress));

    socketAddress->sin_family = AF_INET;
    socketAddress->sin_port = htons(WATCHDOG_PORT);

    if (inet_pton(AF_INET, (const char*) WATCHDOG_IP, &socketAddress->sin_addr) == -1)
    {
        perror("inet_pton");
        exit(EXIT_FAILURE);
    }

    if ((socketfd = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    return socketfd;
}

ssize_t sendTCPpacket(int socketfd, void* buffer, int len) {
    ssize_t sentd = send(socketfd, buffer, len, MSG_DONTWAIT);

    if (sentd == -1)
    {
        kill(pid, SIGKILL);
        perror("send");
        exit(EXIT_FAILURE);
    }

    return sentd;
}

void checkArguments(int argc, char* argv, struct sockaddr_in* dest_in, socklen_t* addr_len) {
    if (argc != 2)
    {
        fprintf(stderr, "Usage: ./ping <ip address>\n");
        exit(EXIT_FAILURE);
    }

    memset(dest_in, 0, sizeof(*dest_in));

    if (inet_pton(AF_INET, argv, &(dest_in->sin_addr)) <= 0)
    {
        fprintf(stderr, "Invalid IP Address\n");
        exit(EXIT_FAILURE);
    }

    dest_in->sin_family = AF_INET;
    
    *addr_len = sizeof(*dest_in);
}

int setupRawSocket(struct icmp *icmphdr, int id) {
    int socketfd = INVALID_SOCKET;

    if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == INVALID_SOCKET)
    {
        perror("socket");
        fprintf(stderr, "To create a raw socket, the process needs to be run by root user.\n");
        exit(EXIT_FAILURE);
    }

    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_id = id;

    return socketfd;
}

void preparePing(char *packet, struct icmp *icmphdr, char *data, size_t datalen) {
    static uint16_t seq = 0;

    bzero(packet, IP_MAXPACKET);

    // Prepares the ICMP packet data
    icmphdr->icmp_seq = htons(++seq);
    icmphdr->icmp_cksum = 0;

    memcpy(packet, icmphdr, ICMP_HDRLEN);
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    icmphdr->icmp_cksum = calculate_checksum((unsigned short *)packet, ICMP_HDRLEN + datalen);
    memcpy(packet, icmphdr, ICMP_HDRLEN);
}

ssize_t sendICMPpacket(int socketfd, char* packet, int datalen, struct sockaddr_in *dest_in, socklen_t len) {
    ssize_t bytes_sent = sendto(socketfd, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)dest_in, len);

    if (bytes_sent == -1)
    {
        kill(pid, SIGKILL);
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    return bytes_sent;
}

ssize_t receiveICMPpacket(int socketfd, void* response, int response_len, struct sockaddr_in *dest_in, socklen_t *len) {
    ssize_t bytes_received = 0;

    bzero(response, IP_MAXPACKET);

    while (!bytes_received)
    {
        bytes_received = recvfrom(socketfd, response, response_len, 0, (struct sockaddr *)dest_in, len);

        if (bytes_received == -1)
        {
            kill(pid, SIGKILL);
            perror("recvfrom");
            exit(EXIT_FAILURE);
        }

        else if (bytes_received > 0)
            break;
    }

    return bytes_received;
}

unsigned short calculate_checksum(unsigned short *paddress, int len) {
    int nleft = len, sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
}