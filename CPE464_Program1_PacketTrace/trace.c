/*
 * Program: trace.c 
 * Description: Sniff packets of network data 
 *     (through provided test packet files)
 *     and print out each layers header information
 * Author: James Caudill
 * Class: CPE 464 Networks
 * Professor: Hugh Smith
 * DateCreated: 16 Jan 2017
 * LastModified: 19 Jan 2017
 */

/* 
 * Includes: pcap.h for network/file packet sniffing
 * arpa/inet.h for inet_ntoa which translates bytewise ips to strings
 * netinet/ether.h for ether_ntoa which is bytewise MAC -> string
 * sys/types and sys/socket for transmission and storage for ntoa's
 * stdlib.h for malloc
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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* Pragma: byte align not word line */
#pragma pack(1)

/* Define: All return values from de-encapsulation*/
#define IP_PACK 5
#define ARP_PACK 6
#define TCP_PACK 7
#define UDP_PACK 8
#define ICMP_PACK 9


/*
 * Structs: All headers for Ethernet, ARP, UDP, ICMP, IP, and TCP 
 */
struct etherHead {
    struct ether_addr dest;
    struct ether_addr src;
    uint16_t type;
};

struct arpHead {
    uint16_t hwType;
    uint16_t protocolType;
    uint8_t hwAddLen;
    uint8_t protocolAddLen;
    uint8_t op;
    struct ether_addr sendMAC;
    struct in_addr sendIP;
    struct ether_addr targMAC;
    struct in_addr targIP;
};

struct icmpHead {
    uint8_t type;
    uint8_t code;
    uint16_t icmpChecksum;
};

struct udpHead {
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t udpLen;
    uint16_t udpChecksum;
};

struct ipHead {
    uint8_t version_IHL;
    uint8_t type;
    uint16_t packLen;
    uint16_t id;
    uint16_t flags_frag;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t ipChecksum;
    struct in_addr src;
    struct in_addr dest;
};

struct tcpHead {
    uint16_t srcPort;
    uint16_t destPort;
    uint32_t seqNum;
    uint32_t ackNum;
    uint8_t dataOff_reserv;
    uint8_t flags;
    uint16_t windowSize;
    uint16_t tcpChecksum;
    uint16_t urgPointer;
};


/*
 * Function to read ethernet frame headers
 * Input: data block and offset to begin reading from
 * Output: an int defining the type of packet encapsulated within
 *     and print to screen ethernet header information
 */
int readEther(uint8_t *data, uint32_t *offset) {
    char *typeString;
    int nextPack;
    struct etherHead *header = malloc(sizeof(struct etherHead));
    
    // copy in all header data 
    memcpy(header, data, sizeof(struct etherHead));
    
    if (ntohs(header->type) == 0x0800) {
        typeString = "IP";
        nextPack = IP_PACK;
    }
    else if (ntohs(header->type) == 0x0806) {
        typeString = "ARP";
        nextPack = ARP_PACK;
    }
    
    fprintf(stdout, "	Ethernet Header\n");
    fprintf(stdout, "		Dest MAC: %s\n", ether_ntoa(&(header->dest)));
    fprintf(stdout, "		Source MAC: %s\n", ether_ntoa(&(header->src)));
    fprintf(stdout, "		Type: %s\n\n", typeString);
    
    *offset = 14;
    
    return nextPack;
}

/*
 * Function to read ARP frame headers
 * Input: pointer to data block (packet), byte offset into packet
 * Output: print to screen details of ARP header
 */
void readARP(uint8_t *data, uint32_t *offset) {
    char *opString;
    struct arpHead *header = malloc(sizeof(struct arpHead));
    
    memcpy(header, data + *offset, sizeof(struct arpHead));
    
    if (ntohl(header->op) == 0x0001) {
        opString = "Request";
    }
    else if (ntohl(header->op) == 0x0002) {
        opString = "Reply";
    }
    
    fprintf(stdout, "   ARP header\n");
    fprintf(stdout, "       Opcode: %s\n", opString);
    fprintf(stdout, "       Sender MAC: %s\n", ether_ntoa(&arpHead->sendMAC));
    fprintf(stdout, "       Sender IP: %s\n", inet_ntoa(arpHead->sendIP));
    fprintf(stdout, "       Target MAC: %s\n", ether_ntoa(&arpHead->targMAC));
    fprintf(stdout, "       Target IP: %s\n\n", inet_ntoa(arpHead->targIP));
    
    *offset += 28;    
    return;
}

/*
 * Function to read ICMP frame headers
 * Input: Address to data block (packet), offset to byte currently on in packet
 * Output: print to screen header information
 */
void readICMP(uint8_t *data, uint32_t *offset) {
    struct icmpHead *header = malloc(sizeof(icmpHead));
    char *typeString;
    
    memcpy(header, data + *offset, sizeof(icmpHead));
    
    if (header->type == 0x00) {
        typeString = "Reply";
    }
    else if (header->type == 0x08) {
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
    struct udpHead *header = malloc(sizeof(struct udpHead));

    memcpy(header, data + *offset, sizeof(struct udpHead));
    
    fprintf(stdout, "    UDP Hearder\n");
    
    // DNS port is 53
    if (ntohs(header->srcPort) == 53) {
        fprintf(stdout, "       Source Port:  DNS\n");
    }
    else {
        fprintf(stdout, "       Source Port:  %u\n", ntohs(header->srcPort);
    }
    
    if (ntohs(header->destPort) == 53) {
        fprintf(stdout, "       Dest Port:  DNS\n\n");
    }
    else {
        fprintf(stdout, "       Dest Port:  %u\n\n", ntohs(header->destPort));
    }
    
    return;
}

/*
 * Function to read TCP headers
 */
void readTCP(uint8_t *data, uint32_t *offset) {
    struct tcpHead *header = malloc(sizeof(struct tcpHead));
    char *synFlag = "No", *rstFlag = "No", *finFlag = "No", *ackFlag = "No";
    
    memcpy(header, data + *offset, sizeof(struct tcpHead));
    
    if (header->flags & 0x02) {
        synFlag = "Yes";
    }
    if (header->flags & 0x04) {
        rstFlag = "Yes";
    }
    if (header->flags & 0x01) {
        finFlag = "Yes";
    }
    if (header->flags & 0x10) {
        ackFlag = "Yes";
    }
    
    fprintf(stdout, "   TCP Header\n")
    fprintf(stdout, "       Source Port:  %u\n", ntohs(header->srcPort));
    fprintf(stdout, "       Dest Port:  %u\n", ntohs(header->destPort));
    fprintf(stdout, "       Sequence Number: %u\n", ntohl(header->seqNum));
    fprintf(stdout, "       ACL Num: %u\n", ntohl(header->ackNum));
    fprintf(stdout, "       Data Offset (bytes): %u\n", (header->dataOff_reserv & 0xF0) >> 4);
    fprintf(stdout, "       SYN Flag: %s\n", synFlag);
    fprintf(stdout, "       RST Flag: %s\n", rstFlag);
    fprintf(stdout, "       FIN Flag: %s\n", finFlag);
    fprintf(stdout, "       ACK Flag: %s\n", ackFlag);
    fprintf(stdout, "       Window Size: %u", ntohs(header->windowSize));
    fprintf(stdout, "       Checksum: \n\n"); //something
    
    return;
}

/*
 * Function to read IP frame headers
 */
int readIP(uint8_t *data, uint32_t *offset) {
    struct ipHead *header = malloc(sizeof(struct ipHead));
    char *prot;
    int nextPack;
    
    memcpy(header, data + *offset, sizeof(struct ipHead));

    if (header->protocol == 6) {
        prot = "TCP";
        nextPack = TCP_PACK;
    }
    else if (header->protocol == 1) {
        prot = "ICMP";
        nextPack = ICMP_PACK;
    }
    else if (header->protocol == 17) {
        prot = "UDP";
        nextPack = UDP_PACK
    }
    else {
        prot = "Other";
        nextPack = 0;
    }

    fprintf(stdout, "	IP Header\n");
    fprintf(stdout, "		IP Version: %u\n", (header->version_IHL & 0xF0) >> 4);
    fprintf(stdout, "		Header Len(bytes): %u\n", header->version_IHL & 0x0F);
    fprintf(stdout, "		TOS subfields:\n");
    fprintf(stdout, "		   Diffserv bits: %u\n", (ntohs(header->id) & 0xFC) >> 2);
    fprintf(stdout, "		   ECN Bits: %u\n", ntohs(header->id) & 0x3);
    fprintf(stdout, "		TTL: %u\n", header->ttl);
    fprintf(stdout, "		Protocol: %s\n", prot); 
    fprintf(stdout, "       Checksum: \n"); //something
    fprintf(stdout, "       Sender IP: %s\n", inet_ntoa(header->src));
    fprintf(stdout, "       Dest IP: %s\n\n", inet_ntoa(header-dest));
    
    *offset += header->version_IHL & 0x0F;
    
    return (nextPack);
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
    struct pcap_pkthdr *pktHeader;
    struct pcap_pkthdr pktHead;
    pktHeader = &pktHead;
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
        fprintf(stdout, "\nPacket number: %u  Packet Len: %u\n\n", pktNum, pktHead.len);
        readPacketData(&pktData, pktHead.len);
    }
    if (err != -2) {
        fprintf(stderr, "Not able to finish read\n");
    }
    
    pcap_close(handler);
    
    return(0);
}
