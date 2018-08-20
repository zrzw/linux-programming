#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>

int
main()
{
        struct addrinfo hints;
        struct addrinfo *servinfo;
        memset(&hints, 0, sizeof hints);
        /* ai_flags settings
         *  AI_PASSIVE: socket is intended for bind() (server)
         *
         */
        // hints.ai_flags = AI_PASSIVE;
        hints.ai_family = AF_UNSPEC; /* Use AF_INET for IPv4 only */
        hints.ai_socktype = SOCK_STREAM;
        int status = getaddrinfo("www.google.com", "80", &hints, &servinfo);
        if(status != 0){
                fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
                exit(1);
        }
        freeaddrinfo(servinfo);
}
