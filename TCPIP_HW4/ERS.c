#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/select.h>

#define PACKET_SIZE 64
#define TIMEOUT_SEC 3  // 超時時間設定為 3 秒

// 計算 ICMP 校驗和
unsigned short checksum(void* b, int nwords) {
    unsigned short *buf = b;
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--){
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff); // check carry out
    sum += (sum >> 16);
    return ~sum; // invert
}

int main(int argc, char *argv[]) {
    if (getenv("SUDO_UID")==NULL){  // Test sudo
        printf("ERROR: You must be root to use this tool.\n");
    }

    if (argc != 3) { // program usage
        printf("Usage: %s <hop_distance> <target_ip>\n", argv[0]);
        return 1;
    }

    char *target_ip = argv[2];
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // create a socket
    if (sock < 0) {
        perror("Socket error");
        return 1;
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(target_ip); // binary IP

    char packet[PACKET_SIZE];
    memset(packet, 0, PACKET_SIZE);

    struct icmphdr *icmp = (struct icmphdr *)packet;
    icmp->type = ICMP_ECHO;
    icmp->code = 0;
    icmp->un.echo.id = getpid();
    icmp->un.echo.sequence = 1;

    int MAX_TTL = atoi(argv[1]);
    char *target_router = NULL;
    for(int ttl = 1; ttl <=MAX_TTL ; ttl++) {
        setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)); //set TTL

        icmp->checksum = 0;
        icmp->checksum = checksum(packet, PACKET_SIZE);

        // 設定接收超時時間
        struct timeval timeout;
        timeout.tv_sec = TIMEOUT_SEC;  // 設定超時
        timeout.tv_usec = 0;

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            perror("setsockopt failed");
            close(sock);
            return 1;
        }

        //send
        sendto(sock, packet, PACKET_SIZE, 0, (struct sockaddr *)&dest, sizeof(dest));

        printf("Sent ICMP packet with TTL = %d to %s\n", ttl, target_ip);

        // 接收回應
        char recv_buff[PACKET_SIZE];
        struct sockaddr_in recv_addr;
        socklen_t len = sizeof(recv_addr);
        
        int recv_size = recvfrom(sock, recv_buff, PACKET_SIZE, 0, (struct sockaddr *)&recv_addr, &len);
        if (recv_size < 0) {
            target_router = NULL;
            printf("Hop %d: * * * (no response)\n", ttl);  // No response, print * * *
        }
        else{
            // store variable
            target_router = inet_ntoa(recv_addr.sin_addr);
            printf("Hop %d: %s\n", ttl, target_router);
        }
        
    }
    close(sock);
        
    printf("The %s is \"%d-hop\" far router from source host to %s\n", target_router, MAX_TTL, target_ip);

    return 0;
}
