/*
 * sample of using getsockname
 *
 * this prints out the local port and IP address as well as the remote
 * port and IP address. 
 *
 * Tested under FreeBSD.
 *
 * Steve Shah (sshah@planetoid.org)
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#define NIPQUAD(addr) \
         ((unsigned char *)&addr)[0], \
         ((unsigned char *)&addr)[1], \
         ((unsigned char *)&addr)[2], \
         ((unsigned char *)&addr)[3]


int main(int argc, char *argv[])
{
    int fdc;
    struct sockaddr_in sin_him, ouraddr;
    socklen_t sin_len;
    int errcode;
    uint16_t dport;
    uint32_t dip;

    if (argc < 3) {
	printf ("Usage: getsockname <ip> <port>\n");
	exit(0);
    }

    dip = inet_addr(argv[1]);
    if (dip == INADDR_NONE) {
	printf ("Invalid IP address\n");
	exit(0);
    }

    dport = atoi(argv[2]);
    if (dport < 1 || dport > 65534) {
	printf ("Invalid port number\n");
	exit(0);
    }

    fdc = socket(PF_INET, SOCK_STREAM, 0);
    if (fdc == -1) {
	perror ("socket() failed");
	exit(0);
    }
    memset((void *)&sin_him, 0, sizeof(sin_him));
    sin_him.sin_family      = AF_INET;
    sin_him.sin_port        = htons(dport);
    sin_him.sin_addr.s_addr = dip;
    sin_len                 = sizeof(struct sockaddr);

    if (connect(fdc, (struct sockaddr *)&sin_him, sin_len) == -1) {
	perror ("connect() failed");
	exit(0);
    }

    errcode = getsockname (fdc, (struct sockaddr *)&ouraddr, &sin_len);
    if (errcode == -1) {
	perror ("getsockname() failed");
	exit(0);
    }

    printf ("Source IP:   %d.%d.%d.%d\n", NIPQUAD(ouraddr.sin_addr.s_addr));
    printf ("Source Port: %d\n", ntohs(ouraddr.sin_port));
    printf ("Dest IP:     %d.%d.%d.%d\n", NIPQUAD(sin_him.sin_addr.s_addr));
    printf ("Dest Port:   %d\n", ntohs(sin_him.sin_port));

    printf ("Sleeping for 10 seconds...\n");
    sleep (10);

    close (fdc);

    return 0;
}

