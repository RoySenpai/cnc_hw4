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
    struct icmp icmphdr;
    struct iphdr *iphdr_res;
    struct icmphdr *icmphdr_res;
    struct sockaddr_in watchdogAddress;
    struct sockaddr_in dest_in;
    struct timeval start, end;

    socklen_t addr_len;
    ssize_t bytes_received = 0;

    char packet[IP_MAXPACKET], response[IP_MAXPACKET];
    char data[ICMP_ECHO_MSG_LEN];
    char responseAddr[INET_ADDRSTRLEN];
    char *args[2];
    char OKSignal = '1';

    int socketfd = INVALID_SOCKET, wdsocketfd = INVALID_SOCKET, datalen;

    double pingPongTime = 0.0;

    signal(SIGUSR1, sighandler);

    for (int i = 0; i < ICMP_ECHO_MSG_LEN - 1; ++i)
        data[i] = '1';

    data[ICMP_ECHO_MSG_LEN - 1] = '\0';
    datalen = (strlen(data) + 1);

    checkArguments(argc, argv[1], &dest_in, &addr_len);

    strcpy(destaddress, argv[1]);

    socketfd = setupRawSocket();
    wdsocketfd = setupTCPSocket(&watchdogAddress);

    args[0] = "./watchdog";
    args[1] = NULL;

    pid = fork();

    if (pid == 0)
    {
        execvp(args[0], args);

        fprintf(stderr, "Error starting watchdog\n");
        perror("execvp");
        exit(errno);
    }

    else
    {
        usleep(WATCHDOG_WAITTIME);

        if (waitpid(pid, &status, WNOHANG) != 0){
            exit(EXIT_FAILURE);
        }

        if (connect(wdsocketfd, (struct sockaddr*) &watchdogAddress, sizeof(watchdogAddress)) == -1)
        {
            kill(pid, SIGKILL);
            perror("connect");
            exit(EXIT_FAILURE);
        }

        memset(&dest_in, 0, sizeof(dest_in));
        dest_in.sin_family = AF_INET;
        dest_in.sin_addr.s_addr = inet_addr(argv[1]);

        addr_len = sizeof(dest_in);

        printf("PING %s: %d data bytes\n", argv[1], datalen);

        while(1)
        {
            preparePing(packet, &icmphdr, data, datalen);

            gettimeofday(&start, NULL);
            sendICMPpacket(socketfd, packet, datalen, &dest_in, sizeof(dest_in));

            bytes_received = receiveICMPpacket(socketfd, response, sizeof(response), &dest_in, &addr_len);

            gettimeofday(&end, NULL);

            sendDataTCP(wdsocketfd, &OKSignal, sizeof(char));

            pingPongTime = ((end.tv_sec - start.tv_sec) * PING_MS) + (((double)end.tv_usec - start.tv_usec) / PING_MS);

            iphdr_res = (struct iphdr *)response;
            icmphdr_res = (struct icmphdr *)(response + iphdr_res->ihl*4);

            inet_ntop(AF_INET, &(iphdr_res->saddr), responseAddr, INET_ADDRSTRLEN);

            printf("%ld bytes from %s: icmp_seq=%d ttl=%d time=%0.3lf ms\n", 
            bytes_received, 
            responseAddr, 
            icmphdr_res->un.echo.sequence, 
            iphdr_res->ttl, 
            pingPongTime);

            usleep(PING_WAIT_TIME);
        }

        close(socketfd);
    }

    wait(&status); // waiting for child to finish before exiting
    printf("child exit status is: %d\n", status);

    return 0;
}

void sighandler(int signum) {
    printf("Server %s cannot be reached.\n", destaddress);
    exit(EXIT_SUCCESS);
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

ssize_t sendDataTCP(int socketfd, void* buffer, int len) {
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

int setupRawSocket() {
    int socketfd = INVALID_SOCKET;

    if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == INVALID_SOCKET)
    {
        perror("socket");
        fprintf(stderr, "To create a raw socket, the process needs to be run by root user.\n");
        exit(EXIT_FAILURE);
    }

    return socketfd;
}

void preparePing(char *packet, struct icmp *icmphdr, char *data, size_t datalen) {
    static uint16_t seq = 0;

    bzero(packet, IP_MAXPACKET);

    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_id = ICMP_ECHO_ID;
    icmphdr->icmp_seq = seq++;
    icmphdr->icmp_cksum = 0;

    memcpy((packet), icmphdr, ICMP_HDRLEN);
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    icmphdr->icmp_cksum = calculate_checksum((unsigned short *)(packet), ICMP_HDRLEN + datalen);
    memcpy((packet), icmphdr, ICMP_HDRLEN);
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