#include "pcap.h"
#include <sys/types.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/time.h>

extern pid_t pid;
extern u16 icmp_req;

// static const char* dev = "eth0";
static const char* dev;

// store the corresponding information
static char* net;
static char* mask;

static char filter_string[FILTER_STRING_SIZE] = "";

static pcap_t *p;
static struct pcap_pkthdr hdr;

char net_copy[INET_ADDRSTRLEN];
char mask_copy[INET_ADDRSTRLEN];

/*
 * This function is almost completed.
 * But you still need to edit the filter string.
 */
void my_pcap_init( const char* dst_ip ,int timeout, const char* device)
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	
	struct in_addr addr;
	
	struct bpf_program fcode;

	dev = device;
	
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
	if(ret == -1){	// failed
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	addr.s_addr = netp;	// network started ip
	net = inet_ntoa(addr);	
	strncpy(net_copy, inet_ntoa(addr), INET_ADDRSTRLEN);	
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	addr.s_addr = maskp;	// ip mask
	mask = inet_ntoa(addr);
	strncpy(mask_copy, inet_ntoa(addr), INET_ADDRSTRLEN);
	if(mask == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	
	// printf("Network: %s\n", net_copy);
    // printf("Mask: %s\n", mask_copy);

	// from device , fetch 8000 bytes
	p = pcap_open_live(dev, 8000, 1, timeout, errbuf);
	if(!p){
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	
	/*
	 *    you should complete your filter string before pcap_compile
	 */
	snprintf(filter_string, FILTER_STRING_SIZE, "((icmp[icmptype] == icmp-echoreply) or arp)");

	if(pcap_compile(p, &fcode, filter_string, 0, maskp) == -1){
		pcap_perror(p,"pcap_compile");
		exit(1);
	}
	
	if(pcap_setfilter(p, &fcode) == -1){
		pcap_perror(p,"pcap_setfilter");
		exit(1);
	}
}


int pcap_get_reply(struct timeval *tv)
{
	const u_char *ptr;

    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(pcap_get_selectable_fd(p), &readfds);  // monitor object
	
	// timeout action
	int ret = select(pcap_get_selectable_fd(p) + 1, &readfds, NULL, NULL, tv);

	if (ret == 0){
		return -2;	// Timeout
	} else if (ret < 0) {
		perror("select()");
        return -2;
	}
	else{
		if (FD_ISSET(pcap_get_selectable_fd(p), &readfds)){
			ptr = pcap_next(p, &hdr);

			if (!ptr) {
				fprintf(stderr, "No packets captured\n");
				return -2; // get null pointer means error.
			}

			// de-encapsulation
			struct ether_header *eth_hdr = (struct ether_header *) (ptr);	// read from ethernet header
			struct iphdr *ip_hdr = (struct iphdr *)((char*)(ptr + 14));  // IP 標頭開始位置
			struct icmphdr *icmp_hdr = (struct icmphdr *)(ptr + 34);

			// Examine ICMP packet

			// Handle ARP
			if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
				// Skip non-ICMP packets (e.g., ARP)
				printf("\tDestination Unreachable.\n");
				return -1;
			}

			// First, get source ip
			char src_ip[INET_ADDRSTRLEN];
			inet_ntop(AF_INET, &(ip_hdr->saddr), src_ip, INET_ADDRSTRLEN);


			// print result
			switch (icmp_hdr->type)
			{
				case ICMP_ECHOREPLY:
					printf("\t Reply from: %s ,", src_ip);
					return 0;
					break;
				case ICMP_DEST_UNREACH:
					printf("\tDestination Unreachable.\n");
				default:
					printf("\tOther ICMP condition.\n");
					break;
			}
		}
	}

	
	
	/*
	 * google "pcap_next" to get more information
	 * and check the packet that ptr pointed to.
	 */
	
	
	return 1;
}