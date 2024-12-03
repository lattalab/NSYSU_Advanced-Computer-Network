#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdbool.h>

#include <sys/ioctl.h>	// find local host ip by ioctl()
#include <net/if.h>
#include <time.h>   // calculte rtt
#include <sys/time.h>

#include "fill_packet.h"
#include "pcap.h"


pid_t pid;

const char* interface_name; // network interface

static char ip[INET_ADDRSTRLEN];  // static allocation
char *data_str = "B103040045";	// stduent ID

struct timeval send_time;  // define send_time
struct timeval recv_time;  // define recv_time

char* get_hostIP(const char* interface_name) {
    int sockfd;
    struct ifreq ifr;

    // create a socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        exit(1);
    }

    // set interface
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    // use ioctl() to find interface, to find the host ip
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl");
        close(sockfd);
        exit(1);
    }

    // retrieve IP
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    strncpy(ip, inet_ntoa(addr->sin_addr), INET_ADDRSTRLEN);

    // close socket
    close(sockfd);

    return ip;
}

// calculate RTT
void calculate_time_diff(struct timeval *start, struct timeval *end) {
    long sec_diff = end->tv_sec - start->tv_sec;
    long usec_diff = end->tv_usec - start->tv_usec;

    if (usec_diff < 0) {  // 微秒部分不足1秒時，需要借1秒
        sec_diff--;
        usec_diff += 1000000;
    }

    // 回傳以毫秒為單位的時間差
    double RTT_ms = sec_diff * 1000 + usec_diff / 1000;
    printf(" time = %lf ms\n", RTT_ms);
}

int main(int argc, char* argv[])
{
	if (argc < 5)   // print usage
        printf("Usage: \"./scanner -i <network_interface_name> -t <timeout (ms)>\"\n");
    else
        printf("Parameters: Network Interface Name = %s, Timeout Threshold = %s (ms).\n", argv[2], argv[4]);

    int sockfd;
	int on = 1;	
	
	pid = getpid();
	u_int16_t seq = 1; // sequence number
	struct sockaddr_in dst;
	myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
	int count = DEFAULT_SEND_COUNT;
	int timeout = (argc == 5) ? atoi(argv[4]) : DEFAULT_TIMEOUT;
	
	/* 
	 * in pcap.c, initialize the pcap
	 */
	interface_name = argv[2];
	char *host_ip = get_hostIP(interface_name);
	my_pcap_init(host_ip , timeout, interface_name);
	if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
	{
		perror("socket");
		exit(1);
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
	{
		perror("setsockopt");
		exit(1);
	}

	/*
	 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
		 or use the standard socket like the one in the ARP homework
 	 *   to get the "ICMP echo response" packets 
	 *	 You should reset the timer every time before you send a packet.
	 */

	struct in_addr net_addr, mask_addr, current_addr, broadcast_addr;

    inet_pton(AF_INET, net_copy, &net_addr);
    inet_pton(AF_INET, mask_copy, &mask_addr);

	// calculate broadcast address
	broadcast_addr.s_addr = net_addr.s_addr | ~mask_addr.s_addr;

	// reverse from first to the end.
	// Loop through the network and send ICMP Echo requests
    for (current_addr.s_addr = ntohl(net_addr.s_addr) + 1; 
		current_addr.s_addr < ntohl(broadcast_addr.s_addr); 
		current_addr.s_addr++) {

        // Convert to xxx.xxx.xxx.xxx format
        char current_ip[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = htonl(current_addr.s_addr);
        inet_ntop(AF_INET, &addr, current_ip, INET_ADDRSTRLEN);

        // Skip own IP address
        if (strcmp(current_ip, host_ip) == 0) {
            continue;
        }


        // Send ICMP Echo requests up to 4 times for each IP
        memset(packet, 0, PACKET_SIZE);  // Clean buffer

        dst.sin_family = AF_INET;       // Use IPv4
        dst.sin_port = 0;     // use port 0
        dst.sin_addr.s_addr = inet_addr(current_ip);  // Set destination IP

        // Fill the ICMP packet
        fill_iphdr((struct iphdr*)&(packet->ip_hdr), current_ip);
        fill_icmphdr((struct icmphdr*)&(packet->icmp_hdr), pid, seq++, 0);

        // Copy data into packet
        memset(packet->data, 0, DATA_LEN);
        memcpy(packet->data, data_str, DATA_LEN);

        // update checksum
        packet->icmp_hdr.checksum = fill_cksum(&(packet->icmp_hdr), ICMP_PACKET_SIZE);

        /*
            set sender side timeout
            (wait until packet receive otherwise resending packet)
        */ 
        struct timeval tv;
        tv.tv_sec = timeout / 1000;
        tv.tv_usec = (timeout % 1000) * 1000;
        if (setsockopt (sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0){
            perror("set timeout failed\n");
        }

        // Send the packet
        gettimeofday(&send_time, NULL);  // sending time
        if (sendto(sockfd, packet, PACKET_SIZE, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
            perror("sendto");
            exit(1);
        } 
        printf("PING %s (data size = 10, id = %x, seq = %d, timeout = %d)\n",
                current_ip, packet->icmp_hdr.un.echo.id, packet->icmp_hdr.un.echo.sequence, timeout);

        // try to receive packet
        for (int i=0; i<count;i++){
            int res = pcap_get_reply(&tv);
            gettimeofday(&recv_time, NULL); // receiving time
            if (!res){
                calculate_time_diff(&send_time, &recv_time);
            }
        }
        

    }

	free(packet);

	return 0;
}

