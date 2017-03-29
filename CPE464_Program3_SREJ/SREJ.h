/*
 * SREJ.h
 *
 *  Created on: Mar 2, 2017
 *      Author: James
 */

#ifndef SREJ_H_
#define SREJ_H_

#define SETUP 1
#define SETUPRESP 2
#define DATA 3
#define RR 5
#define SREJ 6
#define METADATA 7
#define GOODFILE 8
#define BADFILE 9
#define EOF_ACK 10
#define END_OF_FILE 11
#define SENDDATA 12
#define CRC_ERROR -1

#define MAX_LEN 1500
#define MAX_TRIES 10
#define LONG_TIME 10
#define SHORT_TIME 1
#define INTSIZE 4

#pragma pack(1)

#include <cstring>
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <thread>

enum SELECT {
	SET_NULL, NOT_NULL
};

typedef struct header {
	uint32_t seq_num;
	uint16_t checksum;
	uint8_t flag;
} Header;

typedef struct connection {
	int32_t sk_num;
	struct sockaddr_in remote;
	uint32_t len;
} Connection;

typedef struct packet {
	int SREJSent;
	uint32_t seqNum;
	uint32_t packetSize;
	uint8_t bytes[MAX_LEN];
} Packet;


#endif /* SREJ_H_ */
