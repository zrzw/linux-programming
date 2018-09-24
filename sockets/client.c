/*
 * Simple client to resolve hostnames
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <arpa/inet.h>

int main()
{
    struct addrinfo hints;
    struct addrinfo *servinfo;
    memset(&hints, 0, sizeof hints);
    const char* hostname = "google.co.uk";
    const char* port = "80";
    hints.ai_family = AF_INET; /* Use AF_INET for IPv4 only */
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(hostname, port, &hints, &servinfo);
    if(status != 0){
        fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
        exit(1);
    }
    struct addrinfo *p = servinfo;
    while(p != NULL){
        char str[INET_ADDRSTRLEN];
        const char* rc = inet_ntop(p->ai_family,
            &((struct sockaddr_in*) p->ai_addr)->sin_addr,
            str, sizeof(str));
        if(rc != NULL)
            fprintf(stdout, "result: %s\n", str);
        p = p->ai_next;
    }
    freeaddrinfo(servinfo);
}
