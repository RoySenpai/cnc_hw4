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
    // Varibles setup
    struct icmp icmphdr;
    struct iphdr *iphdr_res;
    struct icmphdr *icmphdr_res;
    struct sockaddr_in dest_in;
    struct timeval start, end;

    socklen_t addr_len;
    ssize_t bytes_received = 0;
    size_t datalen;

    int socketfd = INVALID_SOCKET;

    double pingPongTime = 0.0;

    char packet[IP_MAXPACKET], response[IP_MAXPACKET], data[ICMP_ECHO_MSG_LEN], responseAddr[INET_ADDRSTRLEN];

    // Prepare the data we're going to send.
    for (int i = 0; i < ICMP_ECHO_MSG_LEN - 1; ++i)
        data[i] = '1';

    data[ICMP_ECHO_MSG_LEN - 1] = '\0';
    datalen = (strlen(data) + 1);

    // Check the arguments passed to the program and check IP validity.
    checkArguments(argc, argv[1], &dest_in, &addr_len);

    // Prepare the RAW socket.
    socketfd = setupRawSocket(&icmphdr, getpid());

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

        // Calculate the time it took to send and receive the packet
        pingPongTime = ((end.tv_sec - start.tv_sec) * 1000) + (((double)end.tv_usec - start.tv_usec) / 1000);

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

    // Closing the RAW socket and finish.
    close(socketfd);

    return 0;
}

void checkArguments(int argc, char* argv, struct sockaddr_in* dest_in, socklen_t* addr_len) {
    // We must have 2 arguments passed
    if (argc != 2)
    {
        fprintf(stderr, "Usage: ./ping <ip address>\n");
        exit(1);
    }

    memset(dest_in, 0, sizeof(*dest_in));

    // Try to convert the second agument to a binary IPv4 address
    if (inet_pton(AF_INET, argv, &(dest_in->sin_addr)) <= 0)
    {
        fprintf(stderr, "Invalid IP Address\n");
        exit(1);
    }

    dest_in->sin_family = AF_INET;
    
    *addr_len = sizeof(*dest_in);
}

int setupRawSocket(struct icmp *icmphdr, int id) {
    int socketfd = INVALID_SOCKET;

    if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == INVALID_SOCKET)
    {
        fprintf(stderr, "To create a raw socket, the process needs to be run by root user.\n");
        perror("socket");
        exit(1);
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