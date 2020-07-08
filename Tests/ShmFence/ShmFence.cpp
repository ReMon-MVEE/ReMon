/* C/C++ headers */
#include <cstdio>
#include <cstdlib>

/* Linux headers */
#include <pthread.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct shmfence {
    pthread_mutex_t lock;
    pthread_cond_t  wakeup;
    int             value;
    int             waiting;
};

#define MEMFD_SIZE sizeof(struct shmfence) *2
#define SOCKET_NAME "shmfence_socket"

void
shmfence_init(struct shmfence *f) {
  /* Initialize fence */
  pthread_mutexattr_t mutex_attr;
  pthread_condattr_t cond_attr;
  pthread_mutexattr_init(&mutex_attr);
  pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
  pthread_mutex_init(&f->lock, &mutex_attr);

  pthread_condattr_init(&cond_attr);
  pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED);
  pthread_cond_init(&f->wakeup, &cond_attr);
  f->value = 0;
  f->waiting = 0;
}

int
shmfence_trigger(struct shmfence *f) {
    pthread_mutex_lock(&f->lock);
    if (f->value == 0) {
        f->value = 1;
        if (f->waiting) {
            f->waiting = 0;
            pthread_cond_broadcast(&f->wakeup);
        }
    }
    pthread_mutex_unlock(&f->lock);
    return 0;
}

int
shmfence_await(struct shmfence *f) {
    pthread_mutex_lock(&f->lock);
    while (f->value == 0) {
        f->waiting = 1;
        pthread_cond_wait(&f->wakeup, &f->lock);
    }
    pthread_mutex_unlock(&f->lock);
    return 0;
}

void child_main(int sockfd)
{
  /* Receive memfd from parent */
  char            buf[1];
  struct iovec    iov[1];
  struct msghdr   msg;
  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  iov[0].iov_base = buf;
  iov[0].iov_len  = sizeof(buf);
  msg.msg_iov     = iov;
  msg.msg_iovlen  = 1;
  msg.msg_name    = NULL;
  msg.msg_namelen = 0;
  msg.msg_control = cmsgbuf; // make place for the ancillary message to be received
  msg.msg_controllen = sizeof(cmsgbuf);
  recvmsg(sockfd, &msg, 0);

  /* Decode memfd */
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  int memfd;
  if (cmsg == NULL || cmsg -> cmsg_type != SCM_RIGHTS) {
    printf("The first control structure contains no file descriptor.\n");
    exit(0);
  }
  memcpy(&memfd, CMSG_DATA(cmsg), sizeof(memfd));

  /* Map the memfd */
  struct shmfence* f1 = (struct shmfence*)mmap(NULL, MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
  struct shmfence* f2 = f1 +1;
  close(memfd);

  printf("Child is going to trigger!\n");
  shmfence_trigger(f1);
  shmfence_await(f2);
  printf("Child triggered!\n");
}

void parent_main(int sockfd)
{
  /* Create memfd and initialize shared memory */
  int memfd = memfd_create("shmfence_memfd", 0);
  ftruncate(memfd, MEMFD_SIZE);

  /* Map the fence */
  struct shmfence* f1 = (struct shmfence*) mmap(NULL, MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
  struct shmfence* f2 = f1 +1;

  shmfence_init(f1);
  shmfence_init(f2);

  /* Send memfd to child over socket */
  struct msghdr msg;
  memset(&msg,   0, sizeof(msg));
  struct cmsghdr *cmsg;
  char cmsgbuf[CMSG_SPACE(sizeof(memfd))];
  char iobuf[1];
  struct iovec io = {
    .iov_base = iobuf,
    .iov_len = sizeof(iobuf)
  };
  msg.msg_iov = &io;
  msg.msg_iovlen = 1;
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(memfd));
  memcpy(CMSG_DATA(cmsg), &memfd, sizeof(memfd));
  msg.msg_controllen = cmsg->cmsg_len;
  if((sendmsg(sockfd, &msg, 0)) < 0)
  {
    perror("sendmsg()");
    exit(EXIT_FAILURE);
  }
  close(memfd);

  shmfence_await(f1);
  printf("Parent triggered! Now going to trigger child.\n");
  shmfence_trigger(f2);
}

int main()
{
  /* Set up a socketpair so that parent and child are already connected */
  int sockfds[2];
  socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockfds);

  switch(fork())/* Forking before memfd_create leads to a more interesting testcase where the fd still has to be communicated */
  {
    case -1:/*error*/
      {
        perror("fork()");
        exit(EXIT_FAILURE);
      }
    case 0:/*child process*/
      close(sockfds[0]);
      child_main(sockfds[1]);
      break;
    default:/*parent process*/
      close(sockfds[1]);
      parent_main(sockfds[0]);
  }
}
