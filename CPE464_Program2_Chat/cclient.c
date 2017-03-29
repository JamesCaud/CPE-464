/*
 * Program: cclient.c 
 * Description: "Client" program used to initialize one client
 * 		with a chat server accompanied by "Server" program that
 * 		forwards messages to and from clients connected to it
 * Author: James Caudill
 * Class: CPE 464 Networks
 * Professor: Hugh Smith
 * DateCreated: 2 Feb 2017
 * LastModified: 10 Feb 2017
 */

#include <stdint.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "cclient.h"
#include "networks.h"
#include "testing.h"

// global client info stored here
Client *client = NULL;

/*
 * Function: handleArgs
 * Description: reads command line arguments and sets up tcp socket
 * Inputs: argc and argv from main
 * Outputs: server socket number
 */
int handleArgs(int argc, char *argv[]) {

	if (argc != CLIENT_ARGS) {
		fprintf(stderr, "Usage: %s <handle> <server-name> <server-port>", argv[0]);
		exit(0);
	}
	if (strlen(argv[1]) > MAX_HANDLE_LEN - 1) {
		perror("Handle too long.");
		exit(0);
	}

	return tcpClientSetup(argv[2], argv[3]);
}

/*
 * Function: makePacket
 * Description: simple utility function to piece together a header and a data
 * Inputs: A chat header pointer incliuding the length of the packet to make
 * 		A pointer to the rest of the data in the packet
 * Outputs: pointer to new packet
 */
char *makePacket(ChatHeader *head, char *data) {

	char *packet = calloc(1, ntohs(head->len));

	memcpy(packet, head, CHEAD_LEN);
	memcpy(packet + CHEAD_LEN, data, ntohs(head->len) - CHEAD_LEN);

	return packet;
}

/*
 * Function: connectToServer
 * Description: uses desired chat handle to connect to the chat server
 * Inputs: none
 * Outputs: 0 if no connection, 1 if a connection was made
 */
int connectToServer() {

	fd_set fds;
	int dataSent = 0, dataRecv = 0, returnVal = 0;
	ChatHeader *recvPacket = calloc(1, CHEAD_LEN);
	ChatHeader *sendPacket = calloc(1, CHEAD_LEN);
	char *packet;
	char *data = calloc(1, client->handleLen + 1);

	sendPacket->len = htons(client->handleLen + CHEAD_LEN + 1);
	sendPacket->flag = FLAG_1;
	*data = client->handleLen;
	memcpy(data + 1, client->clientHandle, client->handleLen);

	packet = makePacket(sendPacket, data);

	// send data packet over connection
	if ((dataSent = send(client->socket, packet, CONNECT_BUFFER(client->handleLen), 0)) < 0) {
		perror("send failure in conneectToServer");
		exit(0);
	}
	
	FD_ZERO(&fds);
	FD_SET(client->socket, &fds);
	if (select(client->socket + 1, &fds, NULL, NULL, NULL) < 0) {
		perror("selec failure in connect");
	}

	if (FD_ISSET(client->socket, &fds)) {
		// recv confirmation or error
		if ((dataRecv = recv(client->socket, recvPacket, CHEAD_LEN, MSG_WAITALL)) < 0) {
			perror("recv failure in conneectToServer");
			exit(0);
		}

		if (recvPacket->flag == FLAG_3) {
			fprintf(stderr, "Handle already in use: %s", client->clientHandle);
			exit(0);
		}
		else if (recvPacket->flag == FLAG_2) {
			returnVal = 1;
		}
	}
	

	free(packet);
	free(data);
	free(recvPacket);
	free(sendPacket);

	return returnVal;
}

/*
 * Function: findMessage
 * Description: take a packet starting at the beginning of the num handles
 * 				and find the the start of the message
 * Inputs: packet buffer starting at numHandles
 * Outputs: address of the start of the message in the packet buffer
 */
char *findMessage(char *buffer) {

	uint8_t handleLen;
	uint8_t numHandles = *buffer;

	buffer += 1;

	while (numHandles) {
		handleLen = *buffer;
		printf("handleLen: %d", handleLen);
		buffer += handleLen + 1;
		numHandles -= 1;
	}

	return buffer;
}

/*
 * Function: printMessage
 * Description: Super simple function to print out messages
 * Inputs: source handle and message to be printed
 * Outputs: printed message
 */
void printMessage(char *srcHandle, char *message) {

	printf("\n%s: %s\n", srcHandle, message);

	return;
}

/*
 * Function: readMessage
 * Description: read and print message from buffer
 * Inputs: the packet of data
 * Outputs: the sourceHandle: Message
 */
void readMessage(char *buffer) {

	ChatHeader packetHead;
	Handle sendHandle;

	memcpy(&packetHead, buffer, CHEAD_LEN);
	sendHandle.len = *(buffer + CHEAD_LEN);
	memcpy(sendHandle.handle, buffer + 4, sendHandle.len);

	buffer = findMessage(buffer + sendHandle.len + 4);
	printMessage(sendHandle.handle, buffer);

	return;
}

/*
 * Function: readBroadcast
 * Description: read and print message from buffer
 * Inputs: the packet of data
 * Outputs: the sourceHandle: Message
 */
void readBroadcast(char *buffer) {

	ChatHeader packetHead;
	Handle sendHandle;

	memcpy(&packetHead, buffer, CHEAD_LEN);
	sendHandle.len = *(buffer + CHEAD_LEN);
	memcpy(sendHandle.handle, buffer + 4, sendHandle.len);

	printMessage(sendHandle.handle, buffer + sendHandle.len + 4);

	return;
}

/*
 * Function: readBadHandle
 * Description: read off the bad header info received from a flag 7
 * Inputs: the packet of data
 * Outputs: the error message and bad handle
 */
void readBadHandle(char *buffer) {

	ChatHeader packetHead;
	Handle badHandle;

	memcpy(&packetHead, buffer, CHEAD_LEN);
	badHandle.len = *(buffer + CHEAD_LEN);
	memcpy(badHandle.handle, buffer + 4, badHandle.len);

	printf("\nClient with handle %s does not exist.\n", badHandle.handle);

	return;
}

/*
 * Function: disconnectClient
 * Description: close down the socket and clean up global malloc then exit
 * Inputs: none
 * Outputs: this is where normal termination happens
 */
void disconnectClient() {

	close(client->socket);
	free(client);
	client = NULL;

	// successful exit
	exit(1);
}

void readList(char *buffer);
void readListHandles(char *buffer, int numHandles);

/*
 * Function: readPacket
 * Description: read a packet from the server and do work based on its flag
 * Inputs: none
 * Outputs: whatever the flag says to do, do it
 */
void readPacket() {

	ChatHeader packetHead;
	char packet[MAX_PACKET_LEN];

	if(recv(client->socket, &packetHead, CHEAD_LEN, 0) < 0) {
		perror("bad recv in read pack");
		exit(0);
	}

	memcpy(packet, &packetHead, CHEAD_LEN);

	if(recv(client->socket, packet + CHEAD_LEN, packetHead.len, 0) < 0) {
		perror("bad recv2 in read pack");
		exit(0);
	}

	switch(packetHead.flag) {
		case FLAG_4:
			readBroadcast(packet);
			break;
		case FLAG_5:
			readMessage(packet);
			break;
		case FLAG_7:
			readBadHandle(packet);
			break;
		case FLAG_9:
			disconnectClient();
			break;
		case FLAG_11:
			readList(packet);
			break;
		case FLAG_12:
			readListHandles(packet, 0);
			break;
		default:
			fprintf(stderr, "unknown packet");
	}

	return;
}

/*
 * Function: readListHandles
 * Description: read the handles that are on the server a handle at a time
 * Inputs: packet
 * Outputs: handles
 */
void readListHandles(char *buffer, int numHandles) {
	
	printf("%s\n", buffer + 4);

	return;
}

/*
 * Function: readList
 * Description: read the number of clients connect to the server
 * Inputs: packet
 * Outputs; message of number of connected clients
 */
void readList(char *buffer) {

	int numHandles;

	memcpy(&numHandles, buffer + CHEAD_LEN, 4);

	printf("Number of clients: %d\n", ntohl(numHandles));

	return;
}

/*
 * Function: sendMessage
 * Description: send a message to the server with a flag 5
 * 		read from stdin to create right amount of packets
 * 		parse message if longer than 100 bytes
 * Inputs: stdin buffer starting at the beginning '%'
 * Outputs: none
 */
void sendMessage(char *buffer) {

	int messageLen;
	uint8_t numDest = 1, handleLen;
	ChatHeader *packetHead = calloc(1, CHEAD_LEN);
	char *data = calloc(1, MAX_PACKET_LEN);
	char *packet, *curBuf, *dataStart = data;

	packetHead->flag = FLAG_5;

	memcpy(data, &client->handleLen, 1);
	memcpy(data + 1, client->clientHandle, client->handleLen);
	data += client->handleLen + 1;

	curBuf = strtok(buffer, " ");
	curBuf = strtok(NULL, " ");
	buffer += 3;

	if (isdigit(*curBuf)) {
		numDest = (uint8_t) atoi(curBuf);
		printf("numDest: %hhu\n", numDest);
		curBuf = strtok(NULL, " ");
		buffer += 2;
	}

	memcpy(data, &numDest, 1);
	data++;

	while (curBuf != NULL && numDest--) {
		handleLen = strlen(curBuf) + 1;
		memcpy(data, &handleLen, 1);
		memcpy(data + 1, curBuf, handleLen);
		data += handleLen + 1;
		buffer += handleLen;
		if (numDest) {
			curBuf = strtok(NULL, " ");
		}
	}

	if (curBuf == NULL) {
		memcpy(data, "\n", 1);
		packetHead->len = htons((data-dataStart) + CHEAD_LEN + 1);
	}
	else {
		messageLen = strlen(buffer) + 1;

		while (messageLen > 1000) {
			memcpy(data, buffer, 1000);
			packetHead->len = htons(1001 + (data - dataStart) + CHEAD_LEN);
			packet = makePacket(packetHead, dataStart);
			if (send(client->socket, packet, ntohs(packetHead->len), 0) < 0) {
				perror("bad send in sendMessage");
				exit(0);
			}
			free(packet);
			messageLen -= 1000;
			buffer += 1000;
		}

		memcpy(data, buffer, messageLen);
		packetHead->len = htons(messageLen + 1 + (data - dataStart) + CHEAD_LEN);
	}

	packet = makePacket(packetHead, dataStart);
	if (send(client->socket, packet, ntohs(packetHead->len), 0) < 0) {
				perror("bad send in sendMessage");
				exit(0);
	}
	free(packet);
	free(packetHead);
	free(dataStart);

	return;
}


/*
 * Function: sendBroadcast
 * Description: send a broadcast message to the server on flag 4
 * 		just as with the message parsing may be necessary
 * Inputs: stdin buffer starting at the beginning '%'
 * Outputs: none
 */
void sendBroadcast(char *buffer) {

	int messageLen;
	ChatHeader *packetHead = calloc(1, CHEAD_LEN);
	char *data = calloc(1, MAX_PACKET_LEN);
	char *dataStart = data, *packet, *curBuf;

	packetHead->flag = FLAG_4;

	memcpy(data, &client->handleLen, 1);
	memcpy(data + 1, client->clientHandle, client->handleLen);
	data += client->handleLen + 1;

	curBuf = strtok(buffer, " ");
	curBuf += 3;

	if (curBuf == NULL) {
		memcpy(data, "\n", 1);
		packetHead->len = htons((data-dataStart) + CHEAD_LEN + 1);
	}
	else {
		messageLen = strlen(curBuf) + 1;

		while (messageLen > 1000) {
			memcpy(data, curBuf, 1000);
			packetHead->len = htons(1001 + (data - dataStart) + CHEAD_LEN);
			packet = makePacket(packetHead, dataStart);
			if (send(client->socket, packet, ntohs(packetHead->len), 0) < 0) {
				perror("bad send in sendBroadcast");
				exit(0);
			}
			free(packet);
			messageLen -= 1000;
			curBuf += 1000;
		}

		memcpy(data, curBuf, messageLen);
		packetHead->len = htons(messageLen + 1 + (data - dataStart) + CHEAD_LEN);
	}

	packet = makePacket(packetHead, dataStart);
	if (send(client->socket, packet, ntohs(packetHead->len), 0) < 0) {
				perror("bad send in sendBroadcast");
				exit(0);
	}
	free(packet);
	free(packetHead);
	free(dataStart);


	return;
}

/*
 * Function: sendList
 * Description: send a packet to the server with the flag 10
 * Inputs: none
 * Ouputs: none
 */
void sendList() {

	ChatHeader listPacket;

	listPacket.len = htons(CHEAD_LEN);
	listPacket.flag = FLAG_10;

	if (send(client->socket, &listPacket, CHEAD_LEN, 0) < 0) {
		perror(("sendfail in sendlist"));
		exit(0);
	}

	return;
}

/*
 * Function: sendExit
 * Description: send a packet to the server with the flag set to 8
 * Inputs: none
 * Outputs: none
 */
void sendExit() {

	ChatHeader exitPacket;

	exitPacket.len = htons(CHEAD_LEN);
	exitPacket.flag = FLAG_8;

	if (send(client->socket, &exitPacket, CHEAD_LEN, 0) < 0) {
		perror("send fail in sendExit");
		exit(0);
	}

	return;
}

/*
 * Function: readCommand
 * Description: read from stdin buffer the users command
 * Inputs: none
 * Outputs: whatever the command calls for will be handled
 */
void readCommand() {

	char cmdBuf[MAX_BUFF_LEN];

	if (fgets(cmdBuf, MAX_BUFF_LEN, stdin) == NULL) {
		perror("No command received?");
		return;
	}

	if (!strncmp(cmdBuf, "\%M", 2) || !strncmp(cmdBuf, "\%m", 2)) {
		sendMessage(cmdBuf);
	}
	else if (!strncmp(cmdBuf, "\%B", 2) || !strncmp(cmdBuf, "\%b", 2)) {
		sendBroadcast(cmdBuf);
	}
	else if (!strncmp(cmdBuf, "\%L", 2) || !strncmp(cmdBuf, "\%l", 2)) {
		sendList();
	}
	else if (!strncmp(cmdBuf, "\%E", 2) || !strncmp(cmdBuf, "\%e", 2)) {
		sendExit();
	}
	else {
		fprintf(stderr, "Unknown command\n");
	}

	return;
}


/*
 * Function:mainLoop
 * Description: runs main select loop on stdin and server socket
 * Inputs: none
 * Outputs: none
 */
void mainLoop() {

	int selectStatus;
	fd_set fds;

	while(1) {
		printf("$: ");
		fflush(stdout);

		while(1) {
			FD_ZERO(&fds);
			FD_SET(client->socket, &fds);
			FD_SET(STDIN_FILENO, &fds);
			if ((selectStatus = select(client->socket + 1, &fds, NULL, NULL, NULL)) < 0) {
				perror("mainLoop select failure");
				exit(0);
			}
			else if (selectStatus > 0) {
				if (FD_ISSET(client->socket, &fds)) {
					readPacket();
				}
				if (FD_ISSET(STDIN_FILENO, &fds)) {
					readCommand();
				}
				break;
			}
		}
	}

	return;
}


int main(int argc, char *argv[]) {
	
	client = calloc(1, sizeof(Client));

	client->socket = handleArgs(argc, argv);
	client->handleLen = strlen(argv[1]) + 1;
	client->clientHandle = argv[1];


	if (connectToServer() != 1)
		fprintf(stderr, "Did not receive connection flag.");
	
	mainLoop();
	
	return 0;
}
