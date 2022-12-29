#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include "ping_func.h"

int main(int argc, char* argv[]) {
    struct icmp icmphdr;
    struct iphdr *iphdr_res;
    struct icmphdr *icmphdr_res;
    struct sockaddr_in dest_in;
    struct timeval start, end;

    socklen_t addr_len;
    ssize_t bytes_received = 0;

    char packet[IP_MAXPACKET], response[IP_MAXPACKET];
    char data[ICMP_ECHO_MSG_LEN];
    char responseAddr[INET_ADDRSTRLEN];

    int socketfd = INVALID_SOCKET, datalen;

    double pingPongTime = 0.0;

    for (int i = 0; i < ICMP_ECHO_MSG_LEN - 1; ++i)
        data[i] = '1';

    data[ICMP_ECHO_MSG_LEN - 1] = '\0';
    datalen = (strlen(data) + 1);

    checkArguments(argc, argv[1], &dest_in, &addr_len);

    socketfd = setupRawSocket();

    printf("PING %s: %d data bytes\n", argv[1], datalen);

    while(1)
    {
        preparePing(packet, &icmphdr, data, datalen);

        gettimeofday(&start, NULL);
        sendICMPpacket(socketfd, packet, datalen, &dest_in, sizeof(dest_in));

        bytes_received = receiveICMPpacket(socketfd, response, sizeof(response), &dest_in, &addr_len);

        gettimeofday(&end, NULL);

        pingPongTime = ((end.tv_sec - start.tv_sec) * 1000) + (((double)end.tv_usec - start.tv_usec) / 1000);

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

    return 0;
}

void checkArguments(int argc, char* argv, struct sockaddr_in* dest_in, socklen_t* addr_len) {
    if (argc != 2)
    {
        fprintf(stderr, "[PING] Usage: ./ping <ip address>\n");
        exit(1);
    }

    memset(dest_in, 0, sizeof(*dest_in));

    if (inet_pton(AF_INET, argv, &(dest_in->sin_addr)) <= 0)
    {
        fprintf(stderr, "[PING] Invalid IP Address\n");
        exit(1);
    }

    dest_in->sin_family = AF_INET;
    
    *addr_len = sizeof(*dest_in);
}

int setupRawSocket() {
    int socketfd = INVALID_SOCKET;

    if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == INVALID_SOCKET)
    {
        fprintf(stderr, "[PING] To create a raw socket, the process needs to be run by root user.\n");
        perror("socket");
        exit(1);
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
        perror("sendto");
        exit(1);
    }

    return bytes_sent;
}

ssize_t receiveICMPpacket(int socketfd, void* response, int response_len, struct sockaddr_in *dest_in, socklen_t *len) {
    ssize_t bytes_received = 0;

    bzero(response, IP_MAXPACKET);

    while ((bytes_received = recvfrom(socketfd, response, response_len, 0, (struct sockaddr *)dest_in, len)))
    {
        if (bytes_received == -1)
        {
            perror("recvfrom");
            exit(1);
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