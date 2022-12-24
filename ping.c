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

#define INVALID_SOCKET -1
#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8

unsigned short calculate_checksum(unsigned short *paddress, int len);
int setupPing(struct icmp *icmphdr);
int sendPing(int socketfd, char* packet, int datalen, struct sockaddr_in *dest_in, socklen_t len);
ssize_t receivePing(int socketfd, char* response, int response_len, struct sockaddr_in *dest_in, socklen_t *len);

// command: make clean && make all && ./parta

int main(int argc, char* argv[]) {
    struct icmp icmphdr; // ICMP-header
    struct sockaddr_in dest_in;
    struct timeval start, end;
    socklen_t addr_len;
    char packet[IP_MAXPACKET], response[IP_MAXPACKET];
    char data[IP_MAXPACKET] = "Hello, this is a ping checkup, please response.\n";
    int datalen = (strlen(data) + 1), socketfd = INVALID_SOCKET;
    ssize_t bytes_received = 0;
    double pingPongTime = 0.0;

    printf("hello parta\n");

    if (argc != 2)
    {
        fprintf(stderr, "Usage: ./ping <ip address>\n");
        exit(1);
    }

    socketfd = setupPing(&icmphdr);

    memcpy((packet), &icmphdr, ICMP_HDRLEN);
    memcpy(packet + ICMP_HDRLEN, data, datalen);

    icmphdr.icmp_cksum = calculate_checksum((unsigned short *)(packet), ICMP_HDRLEN + datalen);
    memcpy((packet), &icmphdr, ICMP_HDRLEN);

    memset(&dest_in, 0, sizeof(dest_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr(argv[1]);

    addr_len = sizeof(dest_in);

    printf("PING %s: %d data bytes\n", argv[1], datalen);

    while(1)
    {
        gettimeofday(&start, NULL);
        sendPing(socketfd, packet, datalen, &dest_in, sizeof(dest_in));

        bzero(response, IP_MAXPACKET);

        bytes_received = receivePing(socketfd, response, sizeof(response), &dest_in, &addr_len);
        gettimeofday(&end, NULL);

        pingPongTime = ((end.tv_sec - start.tv_sec) * 1000) + (((double)end.tv_usec - start.tv_usec) / 1000);

        struct iphdr *iphdr_res = (struct iphdr *)response;
        struct icmp *icmphdr_res = (struct icmphdr *)((uint32_t *)iphdr_res + iphdr_res->ihl);

        printf("%ld bytes from %s: icmp_seq = %d ttl = %d time = %0.3lf ms\n", bytes_received, argv[1], icmphdr_res->icmp_seq, iphdr_res->ttl, pingPongTime);

        sleep(1);
    }

    close(socketfd);

    return 0;
}

int setupPing(struct icmp *icmphdr) {
    int socketfd = INVALID_SOCKET;

    icmphdr->icmp_type = ICMP_ECHO;
    icmphdr->icmp_code = 0;
    icmphdr->icmp_id = 18;
    icmphdr->icmp_seq = 0;
    icmphdr->icmp_cksum = 0;

    if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == INVALID_SOCKET)
    {
        fprintf(stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        perror("socket");
        exit(1);
    }

    return socketfd;
}

int sendPing(int socketfd, char* packet, int datalen, struct sockaddr_in *dest_in, socklen_t len) {
    int bytes_sent = sendto(socketfd, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *)dest_in, len);

    if (bytes_sent == -1)
    {
        perror("sendto");
        exit(1);
    }

    return bytes_sent;
}

ssize_t receivePing(int socketfd, char* response, int response_len, struct sockaddr_in *dest_in, socklen_t *len) {
    ssize_t bytes_received = 0;
    while ((bytes_received = recvfrom(socketfd, response, response_len, 0, (struct sockaddr *)dest_in, len)))
    {
        if (bytes_received > 0)
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