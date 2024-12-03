#include "fill_packet.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

void 
fill_iphdr ( struct iphdr *ip_hdr , const char* dst_ip)
{
	ip_hdr->ihl = 7; // 28 bytes = 7 * 4 (including ip_options)
    ip_hdr->version = 4;  // IPv4
    ip_hdr->tot_len = htons(PACKET_SIZE); // total length
    
    ip_hdr->id = 0;  // identifier
    ip_hdr->frag_off = htons(IP_DF);  // Don't fragment
    ip_hdr->ttl = 1; // TTL
    ip_hdr->protocol = IPPROTO_ICMP; // ICMP
    ip_hdr->check = 0;     // checksum

    if (inet_pton(AF_INET, dst_ip, &(ip_hdr->daddr)) != 1) {
    perror("inet_pton");
    exit(1);
    }

    // let os do checksum automatically.
}

void
fill_icmphdr (struct icmphdr *icmp_hdr, pid_t pid, u_int16_t seq, int data_len)
{
	icmp_hdr->type = ICMP_ECHO; // echo request
    icmp_hdr->code = 0;

    icmp_hdr->un.echo.id = htons(pid & 0xFFFF);
    icmp_hdr->un.echo.sequence = seq;
    icmp_hdr->checksum = 0;  // assume 0
    // checksum need to consider :
    // icmp_header and icmp_data (B1030400045)
}

u16
fill_cksum(void* icmp_hdr, int data_size)
{
	u16 *buf = icmp_hdr;
    int len = data_size;
    unsigned long sum = 0;
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    /* mop up an odd byte, if necessary */
	if (len == 1)
        sum += *((unsigned char *)buf);

    sum = (sum >> 16) + (sum & 0xffff); // check carry out
    sum = (sum >> 16) + (sum & 0xffff);
    return ~sum; // invert

}