/*
 * Sample program that uses a NetLink socket to print out Linux's routing
 * messages.
 * Source: http://www.wlug.org.nz/LinuxNetlinkSocketExample
 */

/*=============================================================================
    This program can be used to test if the monitor correctly handles netlink
    sockets and especially recvmsg. During execution of this program in the
    MVEE, no mismatches should occur.
=============================================================================*/

#include <asm/types.h>

#include <sys/socket.h>
#include <unistd.h>
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#if 0
//#define MYPROTO NETLINK_ARPD
#define MYMGRP RTMGRP_NEIGH
// if you want the above you'll find that the kernel must be compiled with CONFIG_ARPD, and
// that you need MYPROTO=NETLINK_ROUTE, since the kernel arp code {re,ab}uses rtnl (NETLINK_ROUTE)

#else
#define MYPROTO NETLINK_ROUTE
#define MYMGRP RTMGRP_IPV4_ROUTE
#endif

struct msgnames_t {
        int id;
        char *msg;
} typenames[] = {
#define MSG(x) { x, #x }
        MSG(RTM_NEWROUTE),
        MSG(RTM_DELROUTE),
        MSG(RTM_GETROUTE),
#undef MSG
        {0,0}
};

char *lookup_name(struct msgnames_t *db,int id)
{
        static char name[512];
        struct msgnames_t *msgnamesiter;
        for(msgnamesiter=db;msgnamesiter->msg;++msgnamesiter) {
                if (msgnamesiter->id == id)
                        break;
        }
        if (msgnamesiter->msg) {
                return msgnamesiter->msg;
        }
        snprintf(name,sizeof(name),"#%i",id);
        return name;
}

int open_netlink()
{
        int sock = socket(AF_NETLINK,SOCK_RAW,MYPROTO);
        struct sockaddr_nl addr;

        memset((void *)&addr, 0, sizeof(addr));

        if (sock<0)
                return sock;
        addr.nl_family = AF_NETLINK;
        addr.nl_pid = getpid();
        addr.nl_groups = MYMGRP;
        if (bind(sock,(struct sockaddr *)&addr,sizeof(addr))<0)
                return -1;
        return sock;
}

int read_event(int sock)
{
        struct sockaddr_nl nladdr;
        struct msghdr msg;
        struct iovec iov[2];
        struct nlmsghdr nlh;
        char buffer[65536];
        int ret;
        iov[0].iov_base = (void *)&nlh;
        iov[0].iov_len = sizeof(nlh);
        iov[1].iov_base = (void *)buffer;
        iov[1].iov_len = sizeof(buffer);
        msg.msg_name = (void *)&(nladdr);
        msg.msg_namelen = sizeof(nladdr);
        msg.msg_iov = iov;
        msg.msg_iovlen = sizeof(iov)/sizeof(iov[0]);
        ret=recvmsg(sock, &msg, 0);
        if (ret<0) {
                return ret;
        }
        printf("Type: %i (%s)\n",(nlh.nlmsg_type),lookup_name(typenames,nlh.nlmsg_type));
        printf("Flag:");
#define FLAG(x) if (nlh.nlmsg_flags & x) printf(" %s",#x)
        FLAG(NLM_F_REQUEST);
        FLAG(NLM_F_MULTI);
        FLAG(NLM_F_ACK);
        FLAG(NLM_F_ECHO);
        FLAG(NLM_F_REPLACE);
        FLAG(NLM_F_EXCL);
        FLAG(NLM_F_CREATE);
        FLAG(NLM_F_APPEND);
#undef FLAG
        printf("\n");
        printf("Seq : %i\n",nlh.nlmsg_seq);
        printf("Pid : %i\n",nlh.nlmsg_pid);
        printf("\n");
        return 0;
}

int main(int argc, char *argv[])
{
        int nls = open_netlink();
        if (nls<0) {
                err(1,"netlink");
        }
        
        printf("Waiting for routing events... \n");
	printf("You can connect to/disconnect from a network to generate these\n");
	
        while (1)
                read_event(nls);
        return 0;
}