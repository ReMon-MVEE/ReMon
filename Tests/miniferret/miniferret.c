#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "queue.h"

#define WORKERS 2
#define WORKITEMS 10000

struct workitem
{
  char* work;
  struct workitem* QUEUE_LINK;
};

QUEUE_HEAD(struct workitem) load_queue;
QUEUE_HEAD(struct workitem) stage1_queue;
QUEUE_HEAD(struct workitem) stage2_queue;
QUEUE_HEAD(struct workitem) stage3_queue;

// nr of items enqueued by the load stage
int enqueue_count = 0;
// nr of items dequeued by the out stage
int dequeue_count = 0;
int input_end = 0;

pthread_mutex_t input_mutex;
pthread_mutex_t stage1_mutex;
pthread_mutex_t stage2_mutex;
pthread_mutex_t stage3_mutex;

int stage1_next = 0;
int stage2_next = 1;
int stage3_next = 2;

__thread int tid = 0;

int gettid()
{
  if (tid)
    return tid;

  tid = syscall(224);
  return tid;
}

void* load_thread(void* arg)
{
  for (int i = 0; i < WORKITEMS; ++i)
    {
      struct workitem* __work = (struct workitem*)malloc(sizeof(struct workitem));
      __work->work = (char*)malloc(40);
      sprintf(__work->work, "workitem %d -> ", i);
      pthread_mutex_lock(&input_mutex);
      enqueue_count++;
      pthread_mutex_unlock(&input_mutex);

      queue_enqueue_wait(&load_queue, __work);
    }

  pthread_mutex_lock(&input_mutex);
  input_end = 1;
  pthread_mutex_unlock(&input_mutex);
}

void* stage1_thread(void* arg)
{
  for (;;)
    {
      struct workitem* __work;
      unsigned char rnd;
      unsigned short rnd2;
      queue_dequeue_wait(&load_queue, &__work);

      /*      pthread_mutex_lock(&stage1_mutex);
      stage1_next = stage1_next * 1103515245 + 12345;
      rnd = (unsigned char)((unsigned)(stage1_next/65536) % 5);
      rnd2 = (unsigned short)((unsigned)(stage1_next/65536) % 512);
      pthread_mutex_unlock(&stage1_mutex);

      for (int i = 0; i < rnd; ++i)
	{
	  char* tmp = malloc(i * rnd2);
	  memset(tmp, 0, i*rnd2);
	  free(tmp);
	}
      
      for (int i = 0; i < rnd; ++i)
      sleep(0);*/

      char* modified_workitem = malloc(strlen(__work->work) + strlen("stage 1 tid: 00000 rnd: 00000 - ") + 1);
      sprintf(modified_workitem, "%sstage 1 tid: %d rnd: %d - ", __work->work, gettid(), rnd);
      free(__work->work);
      __work->work = modified_workitem;
  
      queue_enqueue_wait(&stage1_queue, __work);
    }
}

void* stage2_thread(void* arg)
{
  for (;;)
    {
      struct workitem* __work;
      unsigned char rnd;
      unsigned short rnd2;
      queue_dequeue_wait(&stage1_queue, &__work);

      /*      pthread_mutex_lock(&stage2_mutex);
      stage2_next = stage2_next * 1103515245 + 12345;
      rnd = (unsigned char)((unsigned)(stage2_next/65536) % 5);
      rnd2 = (unsigned short)((unsigned)(stage2_next/65536) % 512);
      pthread_mutex_unlock(&stage2_mutex);

      for (int i = 0; i < rnd; ++i)
	{
	  char* tmp = malloc(i * rnd2);
	  memset(tmp, 0, i*rnd2);
	  free(tmp);
	  }*/

      char* modified_workitem = malloc(strlen(__work->work) + strlen("stage 2 tid: 00000 rnd: 00000 - ") + 1);
      sprintf(modified_workitem, "%sstage 2 tid: %d rnd: %d - ", __work->work, gettid(), rnd);
      free(__work->work);
      __work->work = modified_workitem;
      
      /*      for (int i = 0; i < rnd; ++i)
	      sleep(0);*/
  
      queue_enqueue_wait(&stage2_queue, __work);
    }
}

void* stage3_thread(void* arg)
{
  for (;;)
    {
      struct workitem* __work;
      unsigned char rnd;
      unsigned short rnd2;
      queue_dequeue_wait(&stage2_queue, &__work);
	   //queue_dequeue_wait(&load_queue, &__work);

      /*      pthread_mutex_lock(&stage3_mutex);
      stage3_next = stage3_next * 1103515245 + 12345;
      rnd = (unsigned char)((unsigned)(stage3_next/65536) % 5);
      rnd2 = (unsigned short)((unsigned)(stage3_next/65536) % 512);
      pthread_mutex_unlock(&stage3_mutex);

      for (int i = 0; i < rnd; ++i)
	{
	  char* tmp = malloc(i * rnd2);
	  memset(tmp, 0, i*rnd2);
	  free(tmp);
	}

      for (int i = 0; i < rnd; ++i)
      sleep(0);*/

      char* modified_workitem = malloc(strlen(__work->work) + strlen("stage 3 tid: 00000 rnd: 00000 - ") + 1);
      sprintf(modified_workitem, "%sstage 3 tid: %d rnd: %d - ", __work->work, gettid(), rnd);
      free(__work->work);
      __work->work = modified_workitem;
  
      queue_enqueue_wait(&stage3_queue, __work);
    }
}

void* out_thread(void* arg)
{
  for (;;)
    {
      struct workitem* finished_workitem;
      queue_dequeue_wait(&stage3_queue, &finished_workitem);

      dequeue_count++;

      printf("finished workitem %d => %s\n", dequeue_count, finished_workitem->work);
      free(finished_workitem->work);
      free(finished_workitem);

      pthread_mutex_lock(&input_mutex);
      if (input_end && (enqueue_count == dequeue_count))
	{
	  pthread_mutex_unlock(&input_mutex);
	  break;
	}
      pthread_mutex_unlock(&input_mutex);
    }

  return NULL;
}

int main(int argc, char** argv) 
{
  QUEUE_INIT_DEPTH(&load_queue, 400);
  QUEUE_INIT_DEPTH(&stage1_queue, 100);
  QUEUE_INIT_DEPTH(&stage2_queue, 100);
  QUEUE_INIT_DEPTH(&stage3_queue, 100);

  pthread_mutex_init(&input_mutex, NULL);
  pthread_mutex_init(&stage1_mutex, NULL);
  pthread_mutex_init(&stage2_mutex, NULL);
  pthread_mutex_init(&stage3_mutex, NULL);

  // start 1 in and out thread and n threads for each of the stages
  pthread_t out, dummy;
  pthread_create(&dummy, NULL, load_thread, NULL);
  
  for (int i = 0; i < WORKERS; ++i)
    pthread_create(&dummy, NULL, stage1_thread, NULL);
  for (int i = 0; i < WORKERS; ++i)
    pthread_create(&dummy, NULL, stage2_thread, NULL);
  
  for (int i = 0; i < WORKERS; ++i)
    pthread_create(&dummy, NULL, stage3_thread, NULL);
  pthread_create(&out, NULL, out_thread, NULL);

  pthread_join(out, NULL);

  printf("All done!\n");
  return 0;
}
