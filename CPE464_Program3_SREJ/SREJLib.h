/* 
 * SREJLib.h
 *
 * Created on: Mar 10, 2017
 * Author: James
 */

#ifndef SREJLIB_H_
#define SREJLIB_H_

#include "SREJ.h"
#include <stdint.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <stdint.h>
#include <cstdlib>
#include <cstdio>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <thread>

int32_t udpServer(int portNumber);
int32_t sendBuff(uint8_t *buff, uint32_t len, Connection *con, uint8_t flag, uint32_t seqNum, uint8_t *packet);
int32_t createHeader(uint32_t len, uint8_t flag, uint32_t seqNum, uint8_t *packet);
int32_t safeSend(uint8_t *packet, uint32_t len, Connection *con);
int32_t safeRecv(int32_t recv_sk_num, uint8_t *data_buf, int32_t len, Connection *con);
int32_t recvBuff(uint8_t *buf, int32_t len, int32_t recv_sk, Connection *con, uint8_t *flag, uint32_t *seq);
int32_t retHeader(uint8_t *data, int32_t recvLen, uint8_t *flag, uint32_t *seq);
int32_t processSelect(Connection *con, int32_t *retyCount, int32_t timeoutState, int32_t nextState, int32_t doneState);
int32_t select_call(int32_t socket_num, int32_t seconds, int32_t micro, int32_t set_null);

#endif
