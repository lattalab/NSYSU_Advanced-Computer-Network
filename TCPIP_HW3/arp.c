#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
	packet->ea_hdr.ar_hrd = type;
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
	packet->ea_hdr.ar_pro = type;
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
	packet->ea_hdr.ar_hln = size;
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
	packet->ea_hdr.ar_pln = size;
}
void set_op_code(struct ether_arp *packet, short int code)
{
	packet->ea_hdr.ar_op = code;
}

void set_sender_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_sha, address, ETH_ALEN);
}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_spa, address, 4);
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_tha, address, ETH_ALEN);
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
	memcpy(packet->arp_tpa, address, 4);
}

char* get_target_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char* addr = malloc(sizeof(uint8_t)*4);
	memcpy(addr, packet->arp_spa, 4);
	return addr;
}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char* addr = malloc(sizeof(uint8_t)*4);
	memcpy(addr, packet->arp_tpa, 4);
	return addr;
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char* addr = malloc(sizeof(uint8_t)*ETH_ALEN);
	memcpy(addr, packet->arp_sha, ETH_ALEN);
	return addr;
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
	char* addr = malloc(sizeof(uint8_t)*ETH_ALEN);
	memcpy(addr, packet->arp_tha, ETH_ALEN);
	return addr;
}
