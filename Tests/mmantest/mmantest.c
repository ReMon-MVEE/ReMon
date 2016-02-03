#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
 #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>
#include <errno.h>
static int bla1 = 0;
static int bla2 = 0;
static int bla3 = 0;
static int bla4 = 0;
static int bla5 = 0;
static int bla6 = 0;
static int bla7 = 0;
static int bla8 = 0;
static int bla9 = 0;

int main(int argc, char** argv) {
  printf("BSS TEST: bla: %d %d %d %d %d %d %d %d %d\n", bla1, bla2, bla3, bla4, bla5, bla6, bla7, bla8, bla9);

  int fd = open("test.txt", O_CREAT|O_RDWR|O_TRUNC, S_IRWXU);
  printf("file : %d\n", fd);
  write(fd, "test", 5);
  void* test = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  printf("mapped file test @ 0x%08x\n", test);
  close(fd);

  // extend the mapping?
  void* test2 = mmap(test, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  printf("mapped anonymous region @ 0x%08x\n", test2);

  // and again
  void* test3 = mmap(test2, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  void* test4 = mmap(test3, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

  // mprotect 1
  mprotect((void*)((unsigned int)test + 4096), 4096, PROT_READ);
  mprotect(test2, 4096, PROT_READ);
  mprotect(test4, 4096, PROT_READ | PROT_WRITE);

  printf("mprotect round 1 done...\n");

  mprotect((void*)((unsigned int)test + 4096), 4096, PROT_READ | PROT_WRITE);
  mprotect(test2, 4096, PROT_READ | PROT_WRITE);

  // now overwrite the file
  void* test5 = mmap(test, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

  char tmp[512];
  scanf("%s", tmp);

  printf("tagging COW mapping\n");

  sprintf(test, "mehmehmeh");

  printf("tagged\n");

  scanf("%s", tmp);

  int err = munmap(test, 4096);

  scanf("%s", tmp);

  printf("all done... - err: %d (%s)\n", err, strerror(errno));;

  return 0;
}
