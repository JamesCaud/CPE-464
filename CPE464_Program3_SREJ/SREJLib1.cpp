#include "SREJLib.h"
#include "SREJ.h"
#include "cpe464.h"

using namespace std;

int32_t udpServer(int portNumber) {
	int sk = 0;
	struct sockaddr_in local;
	uint32_t len = sizeof(local);
	if ((sk = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		exit(-1);
	}

	local.sin_family = AF_INET;
	local.sin_addr.s_addr = INADDR_ANY;
	local.sin_port = htons(portNumber);
	
	if (bindMod(sk, (struct sockaddr *)&local, sizeof(local)) < 0) {
		perror("udp_server, bind");
		exit(-1);
	}

	getsockname(sk, (struct sockaddr *)&local, &len);
	printf("Using Port #: %d\n", ntohs(local.sin_port));

	return (sk);
}

int32_t sendBuff(uint8_t *buff, uint32_t len, Connection *con, uint8_t flag, uint32_t seqNum, uint8_t *packet) {
	int32_t sentLen = 0;
	int32_t sendingLen = 0;
	
	if (len > 0) {
		memcpy(&packet[sizeof(Header)], buff, len);
	}
	
	sendingLen = createHeader(len, flag, seqNum, packet);
	
	sentLen = safeSend(packet, sendingLen, con);
	
	return sentLen;
}

int32_t createHeader(uint32_t len, uint8_t flag, uint32_t seqNum, uint8_t *packet) {
	Header *head = (Header *) packet;
	uint16_t checksum = 0;
	
	seqNum = htonl(seqNum);
	memcpy(&(head->seq_num), &seqNum, sizeof(seqNum));
	
	head->flag = flag;
	
	memset(&(head->checksum), 0, sizeof(checksum));
	checksum = in_cksum((unsigned short *)packet, len + sizeof(Header));
	memcpy(&(head->checksum), &checksum, sizeof(checksum));
	
	return len + sizeof(Header);
}

int32_t safeSend(uint8_t *packet, uint32_t len, Connection *con) {
	int32_t sendLen = 0;
	
	if((sendLen = sendtoErr(con->sk_num, packet, len, 0, (struct sockaddr *) &(con->remote), con->len)) < 0) {
		perror("SafeSend fail");
		exit(-1);
	}
	
	return sendLen;
}

int32_t safeRecv(int32_t recv_sk_num, uint8_t *data_buf, int32_t len, Connection *con) {
	int32_t recv_len = 0;
	uint32_t remote_len = sizeof(struct sockaddr_in);
	
	if((recv_len = recvfrom(recv_sk_num, data_buf, len, 0, (struct sockaddr *)&(con->remote), &remote_len)) < 0) {
		perror("recvfrom");
		exit(-1);
	}
	
	con->len = remote_len;
	return recv_len;
}

int32_t recvBuff(uint8_t *buf, int32_t len, int32_t recv_sk, Connection *con, uint8_t *flag, uint32_t *seq) {
	uint8_t data[MAX_LEN];
	int32_t recvLen = 0;
	int32_t dataLen = 0;
	
	recvLen = safeRecv(recv_sk, data, len, con);
	
	dataLen = retHeader(data, recvLen, flag, seq);
	
	if (dataLen > 0) {
		memcpy(buf, &data[sizeof(Header)], dataLen);
	}
	
	return dataLen;
}

int32_t retHeader(uint8_t *data, int32_t recvLen, uint8_t *flag, uint32_t *seq) {
	Header *head = (Header *)data;
	int32_t returnVal = 0;
	
	if (in_cksum((unsigned short *)data, recvLen) != 0) {
		returnVal = CRC_ERROR;
	}
	else {
		*flag = head->flag;
		memcpy(seq, &(head->seq_num), sizeof(head->seq_num));
		*seq = ntohl(*seq);
		
		returnVal = recvLen - sizeof(Header);
	}
	
	return returnVal;
}

int32_t processSelect(Connection *con, int32_t *retryCount, int32_t timeoutState, int32_t nextState, int32_t doneState) {
	int32_t returnVal = nextState;
	
	(*retryCount)++;
	if (*retryCount > MAX_TRIES) {
		cout << "Send data " << MAX_TRIES << " times, no ACK. Terminating.\n";
		returnVal = doneState;
	}
	else {
		if(select_call(con->sk_num, SHORT_TIME, 0, NOT_NULL) == 1) {
			*retryCount = 0;
			returnVal = nextState;
		}
		else {
			returnVal = timeoutState;
		}
	}
	
	return returnVal;
}

int32_t select_call(int32_t socket_num, int32_t seconds, int32_t micro, int32_t set_null){
	fd_set fdvar;
	struct timeval time;
	struct timeval *timeout = NULL;
	
	if (set_null == NOT_NULL) {
		time.tv_sec = seconds;
		time.tv_usec = micro;
		timeout = &time;	
	}
	
	FD_ZERO(&fdvar);
	FD_SET(socket_num, &fdvar);
	
	if (select(socket_num +1, (fd_set *)&fdvar, 0, 0, timeout) < 0) {
		perror("select");
		exit(-1);
	}
	
	if (FD_ISSET(socket_num, &fdvar)) {
		return 1;
	}
	else {
		return 0;
	}
}
