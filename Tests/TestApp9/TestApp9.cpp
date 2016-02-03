/*
 * Multi Variant Execution Environment PoC
 * Copyright (C) 2010 Stijn Volckaert <stijnv@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
