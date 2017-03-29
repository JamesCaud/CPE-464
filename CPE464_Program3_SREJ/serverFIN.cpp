/*
 * Program: server.cpp
 * Description: server accepts connections from clients and sends them a file
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

typedef enum State{
	 TIMEOUT, START, DONE, META, SEND_DATA, EOF_STATE
} STATE;


class Window{
private:
	uint32_t lastRR;
	uint32_t botSeq;
	uint32_t topSeq;
	uint32_t lastSeqSent;
	uint32_t lastSeqStored;
	uint32_t windowSize;
	uint32_t EOFseq;
	Packet *windowBuffer;

public:
	Window() {
		lastRR = 0;
		botSeq = 1;
		topSeq = 0;
		lastSeqSent = 0;
		lastSeqStored = 0;
		windowSize = 0;
		EOFseq = 0;
		windowBuffer = NULL;
	}

	void createWindow(uint32_t window) {
		windowSize = window;
		windowBuffer = (Packet *)calloc(windowSize, sizeof(Packet));
		topSeq = windowSize;
	}

	uint32_t getLastRR() {
		return lastRR;
	}

	void setEOFseq(uint32_t val) {
		if (EOFseq == 0) {
			EOFseq = val;
		}
	}

	void setLastRR(uint32_t RRval){
		lastRR = RRval;
	}

	void freeWindow(){
		if (windowBuffer) {
			free(windowBuffer);
			windowBuffer = NULL;
		}
	}

	uint32_t getLastSeqSent() {
		return lastSeqSent;
	}

	uint32_t getEOFseq() {
		return EOFseq;
	}

	uint32_t getLastSeqStored() {
		return lastSeqStored;
	}

	uint32_t getTopSeq() {
		return topSeq;
	}

	uint32_t getBotSeq() {
		return botSeq;
	}

	void moveWindow(uint32_t RRval) {
		botSeq = RRval;
		topSeq = botSeq + windowSize - 1;
	}

	int opentoSend(){
		if (lastSeqSent == lastSeqStored) {
			return 0;
		}
		else {
			return 1;
		}
	}

	int opentoStore(){
		if (lastSeqStored == topSeq) {
			return 0;
		}
		else {
			return 1;
		}
	}

	int readStore(uint32_t dataFile, uint32_t bufSize) {
		int returnVal;

		while (lastSeqStored < topSeq) {
			returnVal = read(dataFile, windowBuffer[(lastSeqStored + 1) % windowSize].bytes, bufSize);

			if (returnVal == -1) {
				perror("read error");
				break;
			}
			else if (returnVal == 0) {
				this->setEOFseq(lastSeqStored + 1);
				break;
			}
			else {
				windowBuffer[(lastSeqStored + 1) % windowSize].packetSize = returnVal;
				windowBuffer[(lastSeqStored + 1) % windowSize].seqNum = lastSeqStored + 1;
				lastSeqStored++;
			}
		}
		//cerr << "Last seq stored: " << lastSeqStored << "\n";

		return returnVal;
	}

	int sendFromWindow(Connection *client, uint8_t *packet) {

		//cerr << "come on\n";
		//cerr << "LastSeqSent: " << lastSeqSent << "\n";
		if (lastSeqSent < lastSeqStored) {
			//cerr << "come on dude\n";
			lastSeqSent++;
			sendBuff(windowBuffer[lastSeqSent % windowSize].bytes,
					windowBuffer[lastSeqSent % windowSize].packetSize, client,
					DATA, windowBuffer[lastSeqSent % windowSize].seqNum, packet);
			//cerr << windowBuffer[lastSeqSent % windowSize].bytes << "\n";
		}
		//else if (lastRR < lastSeqSent) {
		//	this->sentSREJ(client, packet, lastRR);
		//}
	
		return 0;
	}

	void sentSREJ(Connection *client, uint8_t *packet, uint32_t seqNum) {

		sendBuff(windowBuffer[seqNum % windowSize].bytes,
				windowBuffer[seqNum % windowSize].packetSize, client,
				DATA, windowBuffer[seqNum % windowSize].seqNum, packet);
		windowBuffer[seqNum % windowSize].SREJSent++; //maybe for stats later
	}

};

class ServerState {
private:
	double errorPercentage;
	int32_t portNum;
public:

	ServerState() {
		errorPercentage = 0;
		portNum = 0;
	}

	void setError(double error) {
		errorPercentage = error;
	}

	void setPort(int32_t port) {
		portNum = port;
	}

	double getError() {
		return errorPercentage;
	}

	uint32_t getPortNum() {
		return portNum;
	}
};

void serverLoop(ServerState& server, Connection *serverCon);
void clientLoop(Connection *client);
STATE startState(Connection *con, uint8_t *packet);
STATE metaState(Connection *con, Window& win, uint8_t *buf, uint8_t *packet, int32_t *dataFile, uint32_t *bufSize);
STATE sendData(Connection *con, Window& win, uint8_t *buf, uint8_t *packet, int32_t dataFile, uint32_t bufSize, int32_t& retryCnt);
STATE endFile(Connection *con, Window& win, uint8_t *buf, uint8_t *packet, int32_t dataFile, int32_t& retryCnt);

int main(int argc, char *argv[]) {

	Connection *local = (Connection *)calloc(1, sizeof(Connection));
	ServerState server;

	if (argc < 2 || argc > 3) {
		cout << "Incorrect use: server error-percent [port-number]\n";
		return 0;
	}

	if (argc == 2) {
		server.setError(atof(argv[1]));
		server.setPort(0);
	}
	else {
		server.setError(atof(argv[1]));
		server.setPort(atoi(argv[2]));
	}

	sendtoErr_init(server.getError(), DROP_ON, FLIP_ON, DEBUG_ON, RSEED_OFF);


/*	if ((local.sk_num = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socketcall");
		return 0;
	}

	local.len = sizeof(local.remote);
	local.remote.sin_family = AF_INET;
	local.remote.sin_addr.s_addr = INADDR_ANY;
	local.remote.sin_port = htons(server.getPortNum());

	if (bindMod(local.sk_num, (struct sockaddr *)&(local.remote), local.len) < 0) {
		perror("bind error");
		return 0;
	}

	if (getsockname(local.sk_num, (struct sockaddr *)&(local.remote), &(local.len)) < 0) {
		perror("getsockname");
		return 0;
	}

	cout << "Using Port #: " << ntohs(local.remote.sin_port) << "\n";
*/

	local->sk_num = udpServer(server.getPortNum());

	serverLoop(server, local);

	return 1;
}


void serverLoop(ServerState& server, Connection *serverCon) {

	Connection *client = (Connection *)calloc(1, sizeof(Connection));
	uint8_t buf[MAX_LEN];
	uint8_t flag;
	pid_t pid = 0;
	int status = 0;
	uint32_t seq = 0;
	int32_t recvLen = 0;


	while(1) {
		if (select_call(serverCon->sk_num, LONG_TIME, 0, SET_NULL) == 1) {
			recvLen = recvBuff(buf, MAX_LEN, serverCon->sk_num, client, &flag, &seq);
			if (recvLen != CRC_ERROR) {

				if ((pid = fork()) < 0) {
					perror("fork");
					exit(-1);
				}
				if (pid == 0) {
					clientLoop(client);
					exit(0);
				}

				/* thread attempt
				cerr << "got here1.1\n";
				thread clientThread(clientLoop, client);
				cerr << "got here1.2\n";
				clientThread.detach();
				*/
			}
			while (waitpid(-1, &status, WNOHANG) > 0) {
			}
		}
	}

	return;
}

void clientLoop(Connection *client) {

	STATE state = START;
	Connection con;
	Window win;
	uint8_t buf[MAX_LEN];
	uint8_t packet[MAX_LEN];
	int32_t dataFile = 0;
	uint32_t bufSize = 0;
	int32_t retryCnt = 0;

	//cerr << "Got here2\n";
	memcpy(&con, client, sizeof(con));

	while (state != DONE) {
		switch (state) {
		case START:
			state = startState(&con, packet);
			break;
		case META:
			state = metaState(&con, win, buf, packet, &dataFile, &bufSize);
			break;
		case SEND_DATA:
			state = sendData(&con, win, buf, packet, dataFile, bufSize, retryCnt);
			break;
		case EOF_STATE:
			state = endFile(&con, win, buf, packet, dataFile, retryCnt);
			break;
		case DONE:
			cout << "client closing\n";
			win.freeWindow();
			break;
		default:
			cout << "Should not be here.\n";
			break;
		}
	}

	return;
}

STATE startState(Connection *con, uint8_t *packet) {

	if (con->sk_num > 0) {
		close(con->sk_num);
	}
	if ((con->sk_num = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket call");
		exit(-1);
	}

	sendBuff(NULL, 0, con, SETUPRESP, 0, packet);

	return META;
}

STATE metaState(Connection *con, Window& win, uint8_t *buf, uint8_t *packet, int32_t *dataFile, uint32_t *bufSize) {

	STATE returnVal = META;
	uint8_t flag;
	uint32_t seq = 0;
	int32_t recvLen = 0;
	int32_t windowSize;
	int32_t bufferSize;
	uint8_t fname[MAX_LEN];

	if (select_call(con->sk_num, LONG_TIME, 0, SET_NULL) == 1) {
		recvLen = recvBuff(buf, MAX_LEN, con->sk_num, con, &flag, &seq);
		if (recvLen != CRC_ERROR) {
			//cerr << "saw packet\n";
			if (flag == METADATA) {
				memcpy(&windowSize, buf, INTSIZE);
				memcpy(&bufferSize, buf + INTSIZE, INTSIZE);
				strcpy((char*) fname, (char*) buf + (2 * INTSIZE));
				*bufSize = ntohl(bufferSize);

				if ((*dataFile) > 0) {
					close(*dataFile);
				}
				if (((*dataFile) = open((char*) fname, O_RDONLY)) < 0) {
					//cerr << "badFile\n";
					sendBuff(NULL, 0, con, BADFILE, 0, buf);
					returnVal = DONE;
				}
				else {
					//cerr << "dataDile " << *dataFile << "\n";
					sendBuff(NULL, 0, con, GOODFILE, 0, buf);
					returnVal = META;
					win.freeWindow();
					win.createWindow(ntohl(windowSize));
					win.readStore(*dataFile, *bufSize);
				}
			}
			else if (flag == SENDDATA) {
				//cerr << "saw the senddata\n";
				returnVal = SEND_DATA;
			}
		}
	}
	else {
		cout << "Client DC-ed\n";
		returnVal = DONE;
	}

	return returnVal;
}

//stor data to wind when open, check for rr/SREJ, then send packet
STATE sendData(Connection *con, Window& win, uint8_t *buf, uint8_t *packet, int32_t dataFile, uint32_t bufSize, int32_t& retryCnt) {

	STATE returnVal = SEND_DATA;
	STATE procSec = SEND_DATA;
	uint8_t flag;
	uint32_t seq = 0;
	int32_t recvLen = 0;
	uint32_t RRseq = 0;
	uint32_t SREJseq = 0;
	uint32_t goodData;

	//cerr << "in sendData\n";

	if (win.opentoSend()) {
		//cerr << "it better send data\n";
		if (win.sendFromWindow(con, packet) == 1) {
			returnVal = DONE;
		}
	}
	else {
		if ((procSec = (STATE) processSelect(con, &retryCnt, TIMEOUT, SEND_DATA, DONE)) == TIMEOUT) {
			win.sentSREJ(con, packet, win.getBotSeq());
		}
		else if (procSec == DONE) {
			cout << "Client Terminated::Whoops\n";
			return DONE;
		}
	}

	if (select_call(con->sk_num, 0, 0, NOT_NULL) == 1) {
		recvLen = recvBuff(buf,MAX_LEN, con->sk_num, con, &flag, &seq);
		if (recvLen != CRC_ERROR) {
			if (flag == RR) {
				memcpy(&RRseq, buf, INTSIZE);
				RRseq = ntohl(RRseq);
				win.setLastRR(RRseq);
				//cerr << "RRseq: " << RRseq << "\n";
				//cerr << "EOFSeq: " << win.getEOFseq() << "\n";
				if (RRseq == win.getEOFseq()) {
					//cerr << "how did you get herer\n";
					returnVal = EOF_STATE;
					retryCnt = 0;
				}
				else {
					win.moveWindow(RRseq);
					if ((goodData = win.readStore(dataFile, bufSize)) == 0) {
						//win.setEOFseq(win.getLastSeqStored() + 1);
					}
				}
			}
			else if (flag == SREJ) {
				memcpy(&SREJseq, buf, INTSIZE);
				SREJseq = ntohl(SREJseq);
				win.sentSREJ(con, packet, SREJseq);
			}
			else if (flag == SENDDATA) {
				win.sendFromWindow(con, packet);
			}
		}
	}

	return returnVal;
}

//send rest of data and wait on rr for last pack + 1 then send eof processselect
STATE endFile(Connection *con, Window& win, uint8_t *buf, uint8_t *packet, int32_t dataFile, int32_t& retryCnt) {

	STATE returnVal = EOF_STATE;
	uint8_t flag;
	uint32_t seq = 0;
	int32_t recvLen = 0;
	STATE procSec = EOF_STATE;

	sendBuff(NULL, 0, con, END_OF_FILE, win.getEOFseq(), buf);

	if ((procSec = (STATE) processSelect(con, &retryCnt, TIMEOUT, EOF_STATE, DONE)) == EOF_STATE) {
		recvLen = recvBuff(buf, MAX_LEN, con->sk_num, con, &flag, &seq);

		if (recvLen != CRC_ERROR) {
			if (flag == EOF_ACK) {
				returnVal = DONE;
			}
			if (flag == DATA) {
				returnVal = SEND_DATA;
			}
		}
	}
	else if (procSec == DONE) {
		returnVal = DONE;
	}

	return returnVal;
}
