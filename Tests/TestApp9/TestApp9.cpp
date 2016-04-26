#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PATH "/tmp/file"

int
main(int argc, char *argv[])
{
    int sfd;
    struct sockaddr_un addr;

   sfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sfd == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

   memset(&addr, 0, sizeof(struct sockaddr_un));
                        /* Clear structure */
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, PATH,
            sizeof(addr.sun_path) - 1);

   if (bind(sfd, (struct sockaddr *) &addr,
            sizeof(struct sockaddr_un)) == -1)
        perror("bind");

   close(sfd);
   
   unlink(PATH);
   
}
