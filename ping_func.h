#ifndef _PING_FUNC_H
#define _PING_FUNC_H

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>


/* Invalid socket constant */
#define INVALID_SOCKET      -1

/* IP Header length */
#define IP4_HDRLEN          20

/* ICMP Header length */
#define ICMP_HDRLEN         8

/* ICMP ECHO Identifier */
#define ICMP_ECHO_ID        1337

/* ICMP ECHO Message length */
#define ICMP_ECHO_MSG_LEN   32

/* Watchdog IP Address */
#define WATCHDOG_IP         "127.0.0.1"

/* Watchdog TCP Port */
#define WATCHDOG_PORT       3000

/* Watchdog timeout in seconds */
#define WATCHDOG_TIMEOUT    10


/*
 * Function:  checkArguments
 * --------------------
 * A function to check the correctness of the arguments passed.
 *
 *  argc: number of arguments passed
 * 
 *  argv: an array containing all the passed arguments.
 * 
 *  dest_in: a sockaddr_in struct to put the IP address.
 * 
 */
void checkArguments(int argc, char* argv, struct sockaddr_in* dest_in, socklen_t* addr_len);

/*
 * Function:  setupTCPSocket
 * --------------------
 * Setup a TCP socket, depending on need (Watchdog or Ping).
 *
 *  socketAddress: a sockaddr_in struct that contains all the information
 *                  needed to setup a TCP socket.
 *
 *  returns: socket file descriptor if successed,
 *           exit error 1 on fail.
 */
int setupTCPSocket(struct sockaddr_in *socketAddress);

/*
 * Function:  setupRawSocket
 * --------------------
 * Setup a Raw socket, using ICMP IP Protocol.
 *  Used for Ping application.
 *
 *  returns: socket file descriptor if successed,
 *           exit error 1 on fail.
 */
int setupRawSocket();

/*
 * Function:  preparePing
 * --------------------
 * Prepares a ICMP ECHO Packet, with incrementing 
 *  sequence number. Used for Ping application.
 *
 *  packet: a buffer that the packet data will be written to.
 * 
 *  icmphdr: a pointer to an ICMP header that will be written to
 *              to prepare the packet.
 * 
 *  data: the message that the packet will carry
 * 
 *  datalen: message's total length in bytes.
 * 
 */
void preparePing(char *packet, struct icmp *icmphdr, char *data, size_t datalen);

/*
 * Function:  calculate_checksum
 * --------------------
 * Calculates ICMP packet checksum, 
 *  used for the ICMP packet header
 *
 *  paddress: the packet itself.
 * 
 *  len: total size of the packet in bytes.
 *
 *  returns: calculated checksum.
 */
unsigned short calculate_checksum(unsigned short *paddress, int len);

/*
 * Function:  sendICMPpacket
 * --------------------
 * Sends a ICMP packet to a specific address via raw socket.
 *  Used mainly for an ICMP ECHO (a "Ping").
 *
 *  socketfd: socket file descriptor.
 * 
 *  packet: the raw packet data to send.
 * 
 *  datalen: buffer's size.
 * 
 *  dest_in: a sockaddr_in struct that contains all the information
 *              needed to know from where to sent the packet.
 * 
 *  len: length of the sockaddr_in struct
 *
 *  returns: total bytes sent.
 *           exit error 1 on fail.
 */
ssize_t sendICMPpacket(int socketfd, char* packet, int datalen, struct sockaddr_in *dest_in, socklen_t len);

/*
 * Function:  receiveICMPpacket
 * --------------------
 * Receives a ICMP packet via raw socket.
 *  Used mainly for an ICMP ECHO response (a "Pong").
 *
 *  socketfd: socket file descriptor.
 * 
 *  response: a buffer where the received data will be
 *              saved.
 * 
 *  response_len: buffer's size.
 * 
 *  dest_in: a sockaddr_in struct that contains all the information
 *              needed to know from where to receive the packet.
 * 
 *  len: length of the sockaddr_in struct
 *
 *  returns: total bytes received
 *           exit error 1 on fail.
 */
ssize_t receiveICMPpacket(int socketfd, void* response, int response_len, struct sockaddr_in *dest_in, socklen_t *len);

/*
 * Function:  sendDataTCP
 * --------------------
 * Sends data via TCP socket.
 *
 *  socketfd: socket file descriptor.
 * 
 *  buffer: the buffer of data.
 * 
 *  len: buffer size.
 *
 *  returns: total bytes sent,
 *           exit error 1 on fail.
 */
ssize_t sendDataTCP(int socketfd, void* buffer, int len);

/*
 * Function:  receiveDataTCP
 * --------------------
 * Receives data via TCP socket.
 *
 *  socketfd: socket file descriptor.
 * 
 *  buffer: the buffer of data.
 * 
 *  len: buffer size.
 *
 *  returns: total bytes received,
 *           exit error 1 on fail.
 */
ssize_t receiveDataTCP(int socketfd, void *buffer, int len);

#endif