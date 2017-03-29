/*
 * Program: rcopy.cpp
 * Description: rcopy connects to a server with UDP and downloads a file
 * Author: James Caudill
 * Class: CPE 464 Networks
 * Professor: Hugh Smith
 * DateCreated: 2 March 2017
 * LastModified: 9 March 2017
 */

#include "cpe464.h"
#include "SREJ.h"
#include "SREJLib.h"

using namespace std;

typedef enum State {
	DONE, META, RECV_DATA, FILE_OK, START
} STATE;


class Window{
private:
	uint32_t highestRR;
	uint32_t expSeq;
	uint32_t botSeq;
	uint32_t topSeq;
	uint32_t lastSeq;
	uint32_t windowSize;
	Packet *windowBuffer;

public:
	Window() {
		highestRR = 0;
		expSeq = 1;
		botSeq = 1;
		topSeq = 0;
		lastSeq = 0;
		windowSize = 0;
		windowBuffer = NULL;
	}

	void createWindow(uint32_t window) {
		windowSize = window;
		windowBuffer = (Packet*)calloc(windowSize, sizeof(Packet));
		topSeq = windowSize;
	}
	
	uint32_t getTopSeq() {
		return topSeq;
	}

	uint32_t getExpSeq() {
		return expSeq;
	}

	uint32_t getRR() {
		return highestRR;
	}

	void freeWindow(){
		if (windowBuffer) {
			free(windowBuffer);
			windowBuffer = NULL;
		}
	}

	void setRR(uint32_t RRval) {
		highestRR = RRval;
	}

	int SREJTime() {
		if (windowBuffer[(expSeq+1) % windowSize].seqNum == expSeq+1 &&
			windowBuffer[(expSeq+1) % windowSize].packetSize == 0) {
			return 1;
		}
		return 0;
	}

	void setLost(uint32_t seq) {
		windowBuffer[seq % windowSize].SREJSent = 1;
		windowBuffer[seq % windowSize].seqNum = seq;
		windowBuffer[seq % windowSize].packetSize = 0;
	}

	void setLast(uint32_t seq) {
		lastSeq = seq;
	}

	void bufferPacket(uint8_t *buf, uint32_t size, uint32_t seq) {
		memcpy(windowBuffer[seq % windowSize].bytes, buf, size);
		windowBuffer[seq % windowSize].packetSize = size;
		windowBuffer[seq % windowSize].seqNum = seq;
		windowBuffer[seq % windowSize].SREJSent = 0;
	}

	void writePackets(int outFD) {
		//cerr << "you made it to write\n";
		while (windowBuffer[expSeq % windowSize].seqNum == expSeq
				&& windowBuffer[expSeq % windowSize].packetSize != 0) {
			
			write(outFD, windowBuffer[expSeq % windowSize].bytes,
				windowBuffer[expSeq % windowSize].packetSize);
			//cerr << windowBuffer[expSeq % windowSize].bytes << "\n";
			botSeq++;
			topSeq++;
			expSeq++;
		}
		//lastSeq = expSeq - 1;

		highestRR = expSeq;
		//cout << "highest RR: " << highestRR << "\n";
	}
};


class RcopyState{
private:
	uint8_t localFile[100];
	uint8_t remoteFile[100];
	uint32_t windowSize;
	uint32_t bufferSize;
	double errorPercentage;
	uint8_t remoteMachine[100];
	uint32_t remotePort;
	uint32_t sequenceNum;

public:
	RcopyState(char *local, uint32_t localSize, char *remote, uint32_t remoteSize, uint32_t window,
		uint32_t buffer, double error, char *machine, uint32_t machineSize, uint32_t port) {
		
		memcpy(localFile, local, localSize);
		memcpy(remoteFile, remote, remoteSize);
		windowSize = window;
		bufferSize = buffer;
		errorPercentage = error;
		memcpy(remoteMachine, machine, machineSize);
		remotePort = port;
		sequenceNum = 1;
	}

	uint8_t *getRemoteFile() {
		return remoteFile;
	}

	uint8_t *getLocalFile() {
		return localFile;
	}

	uint8_t *getHostName() {
		return remoteMachine;
	}

	uint32_t getWindow(){
		return windowSize;
	}

	int32_t getNetWindow() {
		return htonl(windowSize);
	}

	int32_t getNetBuffer() {
		return htonl(bufferSize);
	}

	void incSeqNum(){
		sequenceNum++;
	}

	uint32_t getSeqNum() {
		return sequenceNum;
	}

	double getError() {
		return errorPercentage;
	}

	uint32_t getPort() {
		return remotePort;
	}
};

STATE startState(RcopyState& state, Connection *server);
STATE meta(RcopyState& state, Connection *server);
STATE fileOK(RcopyState& state, Window& win, Connection *server, int *outFD);
STATE recvData(RcopyState& state, Window& win, int outFD, Connection *server);

int main(int argc, char *argv[]) {

	Connection server;
	int outFD;
	STATE state = START;
	Window win;

	if (argc != 8) {
		cout << "Incorrect argument count\n";
		cout << "USE: rcopy local-file remote-file window-size buffer-size "
				"error-percent remote-machine remote-port\n";
		return 0;
	}

	if (strlen(argv[1]) > 100 || strlen(argv[2]) > 100) {
		cout << "Filename too large: MAX 100 characters\n";
		return 0;
	}

	RcopyState rcopystate(argv[1], strlen(argv[1]) + 1, argv[2], strlen(argv[2]) + 1, atoi(argv[3]),
		atoi(argv[4]), atof(argv[5]), argv[6], strlen(argv[6]) + 1, atoi(argv[7]));

	sendErr_init(rcopystate.getError(), DROP_ON, FLIP_ON, DEBUG_ON, RSEED_OFF);

	while (state != DONE) {
		switch (state) {

		case START:
			state = startState(rcopystate, &server);
			break;

		case META:
			state = meta(rcopystate, &server);
			break;

		case FILE_OK:
			state = fileOK(rcopystate, win, &server, &outFD);
			break;

		case RECV_DATA:
			state = recvData(rcopystate, win, outFD, &server);
			break;

		case DONE:
			win.freeWindow();
			break;

		default:
			cout << "ERROR - in default state\n";
			break;
		}
	}

	return 0;
}

STATE startState(RcopyState& state, Connection *server) {

	STATE returnVal = START;
	int recv_check = 0;
	uint8_t flag = 0;
	uint32_t seqNum;
	struct hostent *hp = NULL;
	uint8_t packet[MAX_LEN];
	static int retryCount = 0;

	if (server->sk_num > 0) {
		close(server->sk_num);
	}

	server->len = sizeof(struct sockaddr_in);

	if ((server->sk_num = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket call");
		exit(-1);
	}

	server->remote.sin_family = AF_INET;

	hp = gethostbyname((char *)state.getHostName());

	if (hp == NULL) {
		perror("Host not found");
		return DONE;
	}

	memcpy(&(server->remote.sin_addr), hp->h_addr, hp->h_length);

	server->remote.sin_port = htons(state.getPort());

	//send hello msg
	sendBuff(NULL, 0, server, SETUP, state.getSeqNum(), packet);

	if ((returnVal = (STATE) processSelect(server, &retryCount, START, META, DONE)) == META) {
		recv_check = recvBuff(packet, MAX_LEN, server->sk_num, server, &flag, &seqNum);

		if (recv_check == CRC_ERROR) {
			returnVal = START;
		}
		else if (flag == SETUPRESP){
			state.incSeqNum();
			returnVal = META;
		}
	}

	return returnVal;
}

STATE meta(RcopyState& state, Connection *server) {

	STATE returnVal = META;
	uint8_t packet[MAX_LEN];
	uint8_t buf[MAX_LEN];
	uint8_t flag = 0;
	uint32_t seqNum = 0;
	uint32_t fnameLen = strlen((char *)state.getRemoteFile()) + 1;
	int32_t recv_check = 0;
	static int retryCnt = 0;
	int32_t netWindow = state.getNetWindow();
	int32_t netBuffer = state.getNetBuffer();

	memcpy(buf, &netWindow, INTSIZE);
	memcpy(&buf[INTSIZE], &netBuffer, INTSIZE);
	memcpy(&buf[2*INTSIZE], state.getRemoteFile(), fnameLen);

	sendBuff(buf, fnameLen + (2 * INTSIZE), server, METADATA, state.getSeqNum(), packet);

	if ((returnVal = (STATE) processSelect(server, &retryCnt, META, FILE_OK, DONE)) == FILE_OK) {
		recv_check = recvBuff(packet, MAX_LEN, server->sk_num, server, &flag, &seqNum);

		if (recv_check == CRC_ERROR) {
			returnVal = META;
		}
		else if (flag == BADFILE) {
			cout << "Error during file open of " <<
				state.getRemoteFile() << " on server.\n";
			returnVal = DONE;
		}
		else if (flag == GOODFILE) {
			state.incSeqNum();
			returnVal = FILE_OK;
		}
	}

	return returnVal;
}

STATE fileOK(RcopyState& state, Window& win, Connection *server, int *outFD) {

	STATE returnVal = FILE_OK;
	uint8_t packet[MAX_LEN];
	static int retryCnt = 0;

	sendBuff(NULL, 0, server, SENDDATA, state.getSeqNum(), packet);

	if ((returnVal = (STATE) processSelect(server, &retryCnt, FILE_OK, RECV_DATA, DONE)) == RECV_DATA) {
		if ((*outFD = open((char *)state.getLocalFile(), O_CREAT | O_TRUNC | O_WRONLY, 0600)) < 0) {
			perror("File open error: ");
			returnVal = DONE;
		}
		else {
			//cerr << "saw the recv\n";
			returnVal = RECV_DATA;
			state.incSeqNum();
			win.createWindow(state.getWindow());
		}
	}

	return returnVal;
}

STATE recvData(RcopyState& state, Window& win, int outFD, Connection *server) {

	uint32_t seqNum = 0;
	uint8_t flag = 0;
	int32_t dataLen = 0;
	uint8_t dataBuf[MAX_LEN];
	uint8_t data[MAX_LEN];
	uint8_t packet[MAX_LEN];
	uint32_t expSeq = win.getExpSeq();
	uint32_t highRR = win.getRR();
	int32_t netExp = htonl(expSeq);
	int32_t netHigh = htonl(highRR);


	if (select_call(server->sk_num, LONG_TIME, 0, NOT_NULL) == 0) {
		cout << "Ten second timeout, server is dead.\n";
		return DONE;
	}
	dataLen = recvBuff(dataBuf, MAX_LEN, server->sk_num, server, &flag, &seqNum);

	//cerr << "EXPSEQ: " << win.getExpSeq() << "\n";
	//cerr << "SEQ: " << seqNum << "\n";
	if(dataLen == CRC_ERROR) {
		return RECV_DATA;
	}
	else if (flag == END_OF_FILE && win.getExpSeq() == seqNum) {
		sendBuff(NULL, 0, server, EOF_ACK, state.getSeqNum(), packet);
		cout << "Download complete.\n";
		//why incSeq lol
		return DONE;
	}
	else if (flag == DATA) {
		if (seqNum > expSeq) {
			netExp = htonl(win.getExpSeq());
			memcpy(data, &netExp, INTSIZE);
			sendBuff(data, INTSIZE, server, SREJ, state.getSeqNum(), packet);
			state.incSeqNum();
			win.setLost(expSeq);
			win.bufferPacket(dataBuf, dataLen, seqNum);
			win.setLast(seqNum);
		}
		else if (seqNum == expSeq) {
			win.bufferPacket(dataBuf, dataLen, seqNum);
			win.writePackets(outFD);
			if (win.SREJTime()) {
				netExp = htonl(win.getExpSeq());
				memcpy(data, &netExp, INTSIZE);
				sendBuff(data, INTSIZE, server, SREJ, state.getSeqNum(), packet);
			}
			else {	
				netHigh = htonl(win.getRR());
				memcpy(data, &netHigh, INTSIZE);
				sendBuff(data, INTSIZE, server, RR, state.getSeqNum(), packet);
				state.incSeqNum();
			}
		}
		else if (seqNum < expSeq) {
			if (win.SREJTime()) {
				netExp = htonl(win.getExpSeq());
				memcpy(data, &netExp, INTSIZE);
				sendBuff(data, INTSIZE, server, SREJ, state.getSeqNum(), packet);
			}
			else {	
				netHigh = htonl(win.getRR());
				memcpy(data, &netHigh, INTSIZE);
				sendBuff(data, INTSIZE, server, RR, state.getSeqNum(), packet);
				state.incSeqNum();
			}
		}
	}

	return RECV_DATA;
}

