/*
 * Program: trace.c 
 * Description: Sniff packets of network data 
 *     (through provided test packet files)
 *     and print out each layers header information
 * Author: James Caudill
 * Class: CPE 464 Networks
 * Professor: Hugh Smith
 * DateCreated: 16 Jan 2017
 * LastModified: 16 Jan 2017
 */

/* 
 * Includes: pcap.h for network/file packet sniffing
 * arpa/inet.h for inet_ntoa which translates bytewise ips to strings
 * netinet/ether.h for ether_ntoa which is bytewise MAC -> string
 * sys/types and sys/socket for transmission and storage for ntoa's
 * stdio.h for printing to system out
 * sting.h for memcpy
 */
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>

/* Pragma: byte align not word line */
#pragma pack(1)

/* Define: All return values from de-encapsulation*/
#define IP_PACK -5
#define ARP_PACK -6
#define TCP_PACK -7
#define UDP_PACK -8
#define ICMP_PACK -9


/*
 * Function to read ethernet frame headers
 * Input: data block and offset to begin reading from
 * Output: an int defining the type of packet encapsulated within
 *     and print to screen ethernet header information
 */
int readEther(uint8_t *data, uint32_t *offset) {
    struct ether_addr *dest;
    struct ether_addr *src;
    uint16_t type;
    char *typeString;
    int nextPack;
    uint8_t *curPoint = data + *offset;
    
    //copy in the data incrementing the pointer simultaneously 
    memcpy(dest, curPoint, 6);
    curPoint += 6;
    memcpy(src, curPoint, 6);
    curPoint += 6;
    memcpy(&type, curPoint, 2);
    
    if (type == 0x0800) {
        typeString = "IP";
        nextPack = IP_PACK;
    }
    else if (type == 0x0806) {
        typeString = "ARP";
        nextPack = ARP_PACK;
    }
    
    fprintf(stdout, "   Ethernet Header\n");
    fprintf(stdout, "       Dest MAC: %s\n", ether_ntoa(dest));
    fprintf(stdout, "       Source MAC: %s\n", ether_ntoa(src));
    fprintf(stdout, "       Type: %s\n\n", typeString);
    
    *offset = 14;
    
    return nextPack;
}

/*
 * Function to read ARP frame headers
 * Input: pointer to data block (packet), byte offset into packet
 * Output: print to screen details of ARP header
 */
void readARP(uint8_t *data, uint32_t *offset) {
    struct ether_addr *sendMAC;
    struct ether_addr *targMAC;
    struct in_addr sendIP;
    struct in_addr targIP;
    uint16_t op;
    char *opString;
    uint8_t *curPoint = data + *offset;
    
    // move the pointer to the opcode bytes
    curPoint += 6;
    
    //copy in the useful data
    memcpy(&op, curPoint, 2);
    curPoint += 2;
    memcpy(sendMAC, curPoint, 6);
    curPoint += 6;
    memcpy(&sendIP, curPoint, 4);
    curPoint += 4;
    memcpy(targMAC, curPoint, 6);
    curPoint += 6;
    memcpy(&targIP, curPoint, 4);
    
    if (op == 0x0001) {
        opString = "Request";
    }
    else if (op == 0x0002) {
        opString = "Reply";
    }
    
    fprintf(stdout, "   ARP header\n");
    fprintf(stdout, "       Opcode: %s\n", opString);
    fprintf(stdout, "       Sender MAC: %s\n", ether_ntoa(sendMAC));
    fprintf(stdout, "       Sender IP: %s\n", inet_ntoa(sendIP));
    fprintf(stdout, "       Target MAC: %s\n", ether_ntoa(targMAC));
    fprintf(stdout, "       Target IP: %s\n\n", inet_ntoa(targIP));
    
    *offset += 28;
    
    return;
}

/*
 * Function to read ICMP frame headers
 * Input: Address to data block (packet), offset to byte currently on in packet
 * Output: print to screen header information
 */
void readICMP(uint8_t *data, uint32_t *offset) {
    uint8_t type;
    char *typeString;
    
    memcpy(&type, data + *offset, 1);
    
    if (type == 0x00) {
        typeString = "Reply";
    }
    else if (type == 0x08) {
        typeString = "Request";
    }
    
    fprintf(stdout, "   ICMP Header\n");
    fprintf(stdout, "       Type: %s\n\n", typeString);
    
    return;
}

/*
 * Function to read UDP frame headers
 * Input: Address to data block (packet), offset to byte currently on in packet
 * Output: print to screen header information
 */
void readUDP(uint8_t *data, uint32_t *offset) {
    uint16_t srcPort;
    uint16_t destPort;
    
    memcpy(&srcPort, data + *offset, 2);
    memcpy(&destPort, data + *offset + 2, 2);
    
    fprintf(stdout, "    UDP Hearder\n");
    
    // DNS port is 53
    if (srcPort == 53) {
        fprintf(stdout, "       Source Port:  DNS\n");
    }
    else {
        fprintf(stdout, "       Source Port:  %u\n", srcPort);
    }
    
    if (destPort == 53) {
        fprintf(stdout, "       Dest Port:  DNS\n\n");
    }
    else {
        fprintf(stdout, "       Dest Port:  %u\n\n", destPort);
    }
    
    return;
}

/*
 * Function to read TCP headers
 */
void readTCP(uint8_t *data, uint32_t *offset) {
    
}

/*
 * Function to read IP frame headers
 */
int readIP(uint8_t *data, uint32_t *offset) {
    
    return (1);
}

/* 
 * Function to read packet data and 
 * call necessary functions to output text
 */
int readPacketData(const uint8_t **data, uint32_t size) {
    uint32_t offset = 0;
    int nextPacket = 0;
    uint8_t *newData;
    memcpy(newData, *data, size);
    
    nextPacket = readEther(newData, &offset);
    if (nextPacket == IP_PACK) {
        nextPacket = readIP(newData, &offset);
        
        if (nextPacket == UDP_PACK) {
            readUDP(newData, &offset);
        }
        else if (nextPacket == ICMP_PACK) {
            readICMP(newData, &offset);
        }
        else if (nextPacket == TCP_PACK) {
            readTCP(newData, &offset);
        }
    }
    else if (nextPacket == ARP_PACK) {
        readARP(newData, &offset);
    }
    
    return(1);
}

int main(int argc, char *argv[]) {
    
    char *file = argv[1];
    char *errbuf;
    pcap_t *handler;
    struct pcap_pkthdr pktHeader;
    const uint8_t *pktData;
    uint8_t err;
    uint32_t pktNum;
    
    // No file was provided in runtime arguments
    if (file == NULL) {
        fprintf(stderr, "No file provided\n");
        return(2);
    }
    
    handler = pcap_open_offline(file, errbuf);
    if (handler == NULL) {
        fprintf(stderr, "Failure opening file %s: %s\n", file, errbuf);
    }
    
    while ((err = pcap_next_ex(handler, &pktHeader, &pktData))) {
        fprintf(stdout, "\nPacket number: %u  Packet Len: %u\n\n", pktNum, pktHeader.len);
        readPacketData(&pktData, pktHeader.len);
    }
    if (err != -2) {
        fprintf(stderr, "Not able to finish read\n");
    }
    
    pcap_close(handler);
    
    return(0);
}
