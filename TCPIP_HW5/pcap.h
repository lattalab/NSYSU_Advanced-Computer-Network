#ifndef __PCAP__H_
#define __PCAP__H_

#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/ip.h> 
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "fill_packet.h"

#define FILTER_STRING_SIZE 100

void my_pcap_init( const char* dst_ip, int timeout, const char* device);

extern char net_copy[INET_ADDRSTRLEN];
extern char mask_copy[INET_ADDRSTRLEN];

int pcap_get_reply(struct timeval *tv);

#endif
