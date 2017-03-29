/*
 * Program: server.c 
 * Description: "Server" program used to receive and forward
 * 		messages sent between "Client" programs
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


ClientList *clientList = NULL;

/*
 * Function: handleArgs
 * Description: checks for a port number then sets up the socket
 * Inputs: argc and argv
 * Outputs: the server socket
 */
int handleArgs(int argc, char *argv[]) {

	int serverSocket = 0;
	struct sockaddr_in local;
	socklen_t len = sizeof(local);
	
	if (argc > 1) {
		if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
			perror("socket call");
			exit(1);
		}
		
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = INADDR_ANY;
		local.sin_port = htons((uint16_t)atoi(argv[1]));
		
		if (bind(serverSocket, (struct sockaddr *) &local, sizeof(local)) < 0) {
			perror("bind call");
			exit(0);
		}
		if (getsockname(serverSocket, (struct sockaddr *) &local, &len) < 0) {
			perror("getsockname call");
			exit(0);
		}
		if (listen(serverSocket, BACKLOG) < 0) {
			perror("listen call");
			exit(0);
		}
	}
	else {
		serverSocket = tcpServerSetup();
	}

	return serverSocket;
}

/*
 * Function: removeClient
 * Description: de-link the client from the list and free it's assets
 * Inputs: client info
 * Outputs: none
 */
void removeClient(Client *client) {

	Client *temp = clientList->firstClient;

	if (client == clientList->firstClient) {
		clientList->firstClient = client->nextClient;
	}
	else {
		while(temp != NULL) {
			if (temp->nextClient == client) {
				temp->nextClient = client->nextClient;
				break;
			}
			temp = temp->nextClient;
		}
	}

	if (client == clientList->lastClient) {
		clientList->lastClient = temp;
	}

	//reset max socket
	if (client->socket == clientList->maxSocket
			&& clientList->firstClient == NULL) {
		clientList->maxSocket = DEFAULT_MAX_SOCKET;
	}

	close(client->socket);
	if (client->clientHandle != NULL) {
		free(client->clientHandle);
	}
	free(client);
	clientList->numClients--;

	return;
}

/*
 * Function: assignHandle
 * Description: reads the data buffer and assigns the client a handle on the list
 * 		checks to see if handle already registered and
 * 		sends the proper response flag
 * Inputs: client info
 * Outputs: none
 */
void assignHandle(Client *client) {

	char *packet = client->data;
	ChatHeader packetHead;
	Handle newHandle;
	Client *curClient = clientList->firstClient;

	packetHead.len = htons(CHEAD_LEN);
	newHandle.len = *(packet + 3);
	memcpy(newHandle.handle, packet + 4, newHandle.len);

	while (curClient != NULL) {
		if (curClient->clientHandle == NULL) {
		}
		else if (!strcmp(curClient->clientHandle, packet + 4)) {
			packetHead.flag = FLAG_3;
			break;
		}
		curClient = curClient->nextClient;
	}

	if (curClient == NULL) {
		packetHead.flag = FLAG_2;
		if (client->clientHandle == NULL) {
			client->clientHandle = calloc(1, newHandle.len);
		}
		else {
			client->clientHandle = realloc(client->clientHandle, newHandle.len);
		}
		strcpy(client->clientHandle, newHandle.handle);
	}

	if (send(client->socket, &packetHead, CHEAD_LEN, 0) < 0) {
		perror("send in assignHandle");
		exit(0);
	}

	if (packetHead.flag == FLAG_3) {
		removeClient(client);
	}
	client->handleLen = strlen(client->clientHandle) + 1;
	return;
}

/*
 * Function: getSocket
 * Description: find the socket num of the clientname passed in
 * Inputs: clientname to find socket for
 * Outputs: -1 if no socket found and the socket if found
 */
int getSocket(char *handle) {

	int clientSocket = -1;
	Client *curClient = clientList->firstClient;

	while (curClient != NULL) {
		if (curClient->clientHandle != NULL) {
			if (!strcmp(handle, curClient->clientHandle)) {
				clientSocket = curClient->socket;
			}
		}
		curClient = curClient->nextClient;
	}

	return clientSocket;
}

/*
 * Function: forwardMessage
 * Description: reads message data and forwards message
 * 		to all dest headers in packet
 * Inputs: client info
 * Outputs: none
 */
void forwardMessage(Client *client) {

	ChatHeader packetHead, badPackHead;
	Handle sendHandle, destHandle;
	uint8_t numDest;
	int socket;
	char *buffer = client->data;
	char *packet = calloc(1, CHEAD_LEN);

	badPackHead.flag = FLAG_7;

	memcpy(&packetHead, buffer, CHEAD_LEN);
	sendHandle.len = *(buffer + CHEAD_LEN);
	memcpy(sendHandle.handle, buffer + 4, sendHandle.len);

	buffer += sendHandle.len + CHEAD_LEN + 1;
	memcpy(&numDest, buffer, 1);
	buffer++;

	while (numDest--) {
		destHandle.len = *buffer;
		memcpy(&(destHandle.handle), buffer + 1, destHandle.len);

		if ((socket = getSocket(buffer + 1)) < 0) {
			badPackHead.len = htons(destHandle.len + 1 + CHEAD_LEN);
			packet = realloc(packet, ntohs(badPackHead.len));
			memcpy(packet, &badPackHead, CHEAD_LEN);
			memcpy(packet + CHEAD_LEN, &destHandle, ntohs(badPackHead.len) - CHEAD_LEN);
			if (send(client->socket, packet, ntohs(badPackHead.len), 0) < 0) {
				perror("send in forward message");
				exit(0);
			}
		}
		else {
			if (send(socket, client->data, ntohs(packetHead.len), 0) < 0) {
				perror("send2 in forward message");
				exit(0);
			}
		}

		buffer += destHandle.len + 1;
	}

	free(packet);
	return;
}

/*
 * Function: forwardBroadcast
 * Description: reads message data and forwards message
 * 		to all dest headers in list (except src)
 * Inputs: client info
 * Outputs: none
 */
void forwardBroadcast(Client *client) {

	ChatHeader packetHead;
	Handle sendHandle;
	char *buffer = client->data;
	Client *curClient = clientList->firstClient;

	memcpy(&packetHead, buffer, CHEAD_LEN);
	sendHandle.len = *(buffer + CHEAD_LEN);
	memcpy(sendHandle.handle, buffer + 4, sendHandle.len);

	while (curClient != NULL) {
		if (curClient->clientHandle != NULL &&
				strcmp(sendHandle.handle, curClient->clientHandle)) {
			if (send(curClient->socket, client->data, ntohs(packetHead.len), 0) < 0) {
				perror("bad send in forward broadcast");
				exit(0);
			}
		}
		curClient = curClient->nextClient;
	}

	return;
}

/*
 * Function: clientExit
 * Description: closes socket and removes client from list
 * 		responds to client with flag 9
 * Inputs: client info
 * Outputs: none
 */
void clientExit(Client *client) {

	int dataSent = 0;
	ChatHeader sendHead;
	sendHead.len = htons(CHEAD_LEN);
	sendHead.flag = FLAG_9;

	if ((dataSent = send(client->socket, &sendHead, CHEAD_LEN, 0)) < 0) {
		perror("bad send in clientExit");
	}

	removeClient(client);

	return;
}

/*
 * Function: listRequest
 * Description: responds to client with num clients and all clients
 * 		with flag 11 then a set of 12s
 * Inputs: client info
 * Outputs: none
 */
void listRequest(Client *client) {

	Client *curClient = clientList->firstClient;
	ListPacket listPack;
	ChatHeader packetHead;
	uint16_t packetLen, dataSent;
	char *data = malloc(CHEAD_LEN);

	listPack.len = htons(CHEAD_LEN + 4);
	listPack.flag = FLAG_11;
	listPack.numHandles = htonl(clientList->numClients);

	if (send(client->socket, &listPack, CHEAD_LEN + 4, 0) < 0) {
		perror("send1 in ListReq");
		exit(0);
	}

	packetHead.flag = FLAG_12;

	while (curClient != NULL) {
		if (curClient->clientHandle != NULL) {
			packetLen = CHEAD_LEN + curClient->handleLen + 1;
			
			data = realloc(data, packetLen);
			packetHead.len = htons(packetLen);

			memcpy(data, &packetHead, CHEAD_LEN);
			memcpy(data + CHEAD_LEN, &curClient->handleLen, 1);
			memcpy(data + CHEAD_LEN + 1, curClient->clientHandle, curClient->handleLen);

			if ((dataSent = send(client->socket, data, packetLen, 0)) < 0) {
				perror("send2 in ListReq");
				exit(0);
			}
		}
		
		curClient = curClient->nextClient;
	}

	free(data);

	return;
}

/*
 * Function: handleClient
 * Description: handles the clients request and sends packet off to other funcs
 * Inputs: client info
 * Outputs: none
 */
void handleClient(Client *client) {

	int dataRecv;
	char *buffer = calloc(1, MAX_PACKET_LEN);

	if (buffer == NULL) {
		perror("bad calloc in handleClient");
		exit(0);
	}

	if ((dataRecv = recv(client->socket, buffer, MAX_PACKET_LEN, 0)) < 0) {
		perror("bad recv in handleClient");
		free(buffer);
		exit(0);
	}
	//abrupt shutdown
	if (dataRecv == 0) {
		removeClient(client);
	}
	else {
		client->data = buffer;
		switch (*(buffer + 2)) {
			case FLAG_1:
				assignHandle(client);
				break;
			case FLAG_4:
				forwardBroadcast(client);
				break;
			case FLAG_5:
				forwardMessage(client);
				break;
			case FLAG_8:
				clientExit(client);
				break;
			case FLAG_10:
				listRequest(client);
				break;
			default:
				printf("bad packet received\n");
				break;
		}
		client->data = NULL;
	}

	free(buffer);

	return;
}

/*
 * Function: fdsSetClients
 * Description: marks all the sockets for select
 * Inputs: the fd set
 * Outputs: none
 */
void fdSetClients(fd_set *fds) {

	Client *curClient = clientList->firstClient;

	while (curClient != NULL) {
		FD_SET(curClient->socket, fds);
		curClient = curClient->nextClient;
	}

	return;
}

/*
 * Function: fdsIsSetClients
 * Description: checks to see if any of the clients have something to read from
 * Inputs: tthe fd set
 * Outputs: noone
 */
void fdIsSetClients(fd_set *fds) {

	Client *curClient = clientList->firstClient;

	while (curClient != NULL) {
		if (FD_ISSET(curClient->socket, fds)) {
			handleClient(curClient);
		}
		curClient = curClient->nextClient;
	}

	return;
}

/*
 * Function: newClient
 * Description: create a client and get its socket and add to list
 * 		update maxSocket/firstClient/LastClient if necessary
 * Inputs: the server socket
 * Outputs: none
 */
void newClient(int socket) {

	Client *newClient = calloc(1, sizeof(Client));

	if (newClient == NULL) {
		perror("Calloc error in newClient");
		exit(0);
	}

	if ((newClient->socket = accept(socket, (struct sockaddr*)0, (socklen_t *)0)) < 0) {
		perror("bad accept call in newClient");
		free(newClient);
		exit(0);
	}

	newClient->clientHandle = NULL;

	if (clientList->firstClient == NULL || clientList->lastClient == NULL) {
		clientList->firstClient = newClient;
		clientList->lastClient = newClient;
	}
	else {
		clientList->lastClient->nextClient = newClient;
		clientList->lastClient = newClient;
	}

	if (newClient->socket > clientList->maxSocket) {
		clientList->maxSocket = newClient->socket;
	}

	clientList->numClients++;

	return;
}

/*
 * Function: mainLoop
 * Description: main select loop through all clients and server socket
 * Inputs: the server socket
 * Outputs: none
 */
void mainLoop(int inSock) {

	int selectStatus;
	fd_set fds;

	while (1) {
		FD_ZERO(&fds);
		FD_SET(inSock, &fds);

		fdSetClients(&fds);

		if ((selectStatus =
				select(clientList->maxSocket + 1, &fds, NULL, NULL, NULL)) < 0) {
			perror("select failure");
			exit(0);
		}
		else if (selectStatus > 0) {
			if (FD_ISSET(inSock, &fds)) {
				newClient(inSock);
				continue;
			}
			fdIsSetClients(&fds);
		}
	}

	return;
}

int main(int argc, char *argv[])
{
	int serverSocket = 0;

	clientList = calloc(1, sizeof(ClientList));
	clientList->maxSocket = DEFAULT_MAX_SOCKET;
	clientList->firstClient = NULL;
	clientList->lastClient = NULL;
	clientList->numClients = 0;
	
	serverSocket = handleArgs(argc, argv);

	mainLoop(serverSocket);
	
	close(serverSocket);
	return 0;
}
