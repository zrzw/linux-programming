/*
 * rawdns.c - craft DNS packets using raw sockets
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#define IPHDR_SIZE 20
#define UDPHDR_SIZE 8
#define MAX_DNS_PAYLOAD_SIZE 512

int rawdns(const char* hostname);
void print_hdr_sizes(void);

int rawdns(const char* ip_str)
{
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if(s == -1){
        fprintf(stderr, "Error creating raw socket\n");
        return -1;
    }
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    int rc = inet_pton(AF_INET, ip_str, &(sa.sin_addr.s_addr));
    if(rc != 1){
        fprintf(stderr, "Error filling sockaddr_in with given IP STR\n");
        return -1;
    }
    sa.sin_port = htons(53);
    return 0;
}

void print_hdr_sizes(void)
{
    printf("Size of struct iphdr: %zu\n", sizeof(struct iphdr));
    printf("Size of struct udphdr: %zu\n", sizeof(struct udphdr));
}

int main(int argc, char** argv)
{
    print_hdr_sizes();
    return rawdns("4.4.4.4");
}
