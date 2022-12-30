/*
 *  Communication and Computing Course Assigment 4:
 *  RAW Sockets and ICMP Protocol
 *  Copyright (C) 2022-2023  Roy Simanovich and Yuval Yurzdichinsky
 *  
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#ifndef _PING_FUNC_H
#define _PING_FUNC_H

#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>


/* Invalid socket constant */
#define INVALID_SOCKET      -1

/* Max length of an IPv4 address */
#define IP4_MAXLEN          16

/* ICMP Header length */
#define ICMP_HDRLEN         8

/* ICMP ECHO Message length */
#define ICMP_ECHO_MSG_LEN   32

/* Watchdog IP Address */
#define WATCHDOG_IP         "127.0.0.1"

/* Watchdog TCP Port */
#define WATCHDOG_PORT       3000

/* Watchdog timeout in seconds. */
#define WATCHDOG_TIMEOUT    10

/* Defines the wait time in ms after receiving an ICMP ECHO REPLAY packet. */
#define PING_WAIT_TIME      (1000 * 1000)

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
 *           exit error errno on fail.
 */
int setupTCPSocket(struct sockaddr_in *socketAddress);

/*
 * Function:  setupRawSocket
 * --------------------
 * Setup a Raw socket, using ICMP IP Protocol.
 *  Used for Ping application.
 * 
 *  icmphdr: a pointer to an ICMP header that will be written to
 *              to prepare the packet.
 * 
 *  id: ID that will be used to identify ICMP ECHO and
 *              ICMP ECHO REPLAY packets.
 *
 *  returns: socket file descriptor if successed,
 *           exit error errno on fail.
 */
int setupRawSocket(struct icmp *icmphdr, int id);

/*
 * Function:  setSocketNonBlocking
 * --------------------
 * Set the given socket to use Non-Blocking I/O mode.
 * 
 *  socketfd: socket file descriptor.
 *
 *  returns: 1 if successed,
 *           exit error errno on fail.
 */
int setSocketNonBlocking(int socketfd);

/*
 * Function:  preparePing
 * --------------------
 * Prepares a ICMP ECHO Packet, with incrementing 
 *  sequence number. Used for Ping application.
 *
 *  packet: a buffer that the packet data #include <sys/poll.h>will be written to.
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
 *           exit error errno on fail.
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
 *           exit error errno on fail.
 */
ssize_t receiveICMPpacket(int socketfd, void* response, int response_len, struct sockaddr_in *dest_in, socklen_t *len);

/*
 * Function:  sendTCPpacket
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
 *           exit error errno on fail.
 */
ssize_t sendTCPpacket(int socketfd, void* buffer, int len);

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
 *           exit error errno on fail.
 */
ssize_t receiveTCPpacket(int socketfd, void *buffer, int len);

#endif