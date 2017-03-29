#ifndef CCLIENT_H
#define CCLIENT_H

#pragma pack(1)

// ALL Packet Flags
#define FLAG_1 0x1
#define FLAG_2 0x2
#define FLAG_3 0x3
#define FLAG_4 0x4
#define FLAG_5 0x5
#define FLAG_6 0x6
#define FLAG_7 0x7
#define FLAG_8 0x8
#define FLAG_9 0x9
#define FLAG_10 0xA
#define FLAG_11 0xB
#define FLAG_12 0xC

#define CHEAD_LEN 3
#define MAX_BUFF_LEN 4096
#define MAX_HANDLE_LEN 250
#define MAX_MSG_LEN 1000
#define MAX_PACKET_LEN 4096
#define DEFAULT_MAX_SOCKET 3

// All Possible Error Codes
#define TOO_LITTLE_ARGS -4
#define MALLOC_ERROR -5

// used for argument handling
#define CLIENT_ARGS 4

// used for client-server connection
#define CONNECT_BUFFER(handleLen) (handleLen + 4)

typedef struct Handle {
	uint8_t len;
	char handle[MAX_HANDLE_LEN];
} Handle;

typedef struct ChatHeader {
    uint16_t len;
    uint8_t flag;
} ChatHeader;

typedef struct Client {
	int socket;
	uint8_t handleLen;
	char *clientHandle;
	struct Client *nextClient;
	char *data;
} Client;

typedef struct ClientList {
	struct Client *firstClient;
	struct Client *lastClient;
	int maxSocket;
	int numClients;
} ClientList;

typedef struct ListPacket {
	uint16_t len;
	uint8_t flag;
	uint32_t numHandles;
} ListPacket;

#endif
