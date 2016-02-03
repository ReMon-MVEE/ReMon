/*
Source: http://publib.boulder.ibm.com/html/as400/ic2924/info/RZAHWM53.HTM
Filename: ATEST18.QCSRC
The output of this example is as follows:
 Enter Testcase - LIBRARY/ATEST18
 Create/start threads
 Producer: 'Finding' data
 Consumer Thread 00000000 00000022: Entered
 Consumer Thread 00000000 00000023: Entered
 Consumer Thread 00000000 00000022: Wait for data to be produced
 Consumer Thread 00000000 00000023: Wait for data to be produced
 Producer: Make data shared and notify consumer
 Producer: Unlock shared data and flag
 Producer: 'Finding' data
 Consumer Thread 00000000 00000022: Found data or Notified, CONSUME IT while holding lock
 Consumer Thread 00000000 00000022: Wait for data to be produced
 Producer: Make data shared and notify consumer
 Producer: Unlock shared data and flag
 Producer: 'Finding' data
 Consumer Thread 00000000 00000023: Found data or Notified, CONSUME IT while holding lock
 Consumer Thread 00000000 00000023: Wait for data to be produced
 Producer: Make data shared and notify consumer
 Producer: Unlock shared data and flag
 Producer: 'Finding' data
 Consumer Thread 00000000 00000022: Found data or Notified, CONSUME IT while holding lock
 Consumer Thread 00000000 00000022: All done
 Producer: Make data shared and notify consumer
 Producer: Unlock shared data and flag
 Wait for the threads to complete, and release their resources
 Consumer Thread 00000000 00000023: Found data or Notified, CONSUME IT while holding lock
 Consumer Thread 00000000 00000023: All done
 Clean up
 Main completed
*/

#define _MULTI_THREADED
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <asm/unistd_32.h>

#define checkResults(string, val) {             \
 if (val) {                                     \
   printf("Failed with %d at %s", val, string); \
   exit(1);                                     \
 }                                              \
}

#define                 NUMTHREADS     2
pthread_mutex_t         dataMutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t          dataPresentCondition = PTHREAD_COND_INITIALIZER;
int                     dataPresent=0;
int                     sharedData=0;

int gettid()
{
    return syscall(__NR_gettid);
}

void *theThread(void *parm)
{
   int   rc;
   int   retries=2;
   struct timespec abstime;

   printf("Consumer Thread %.8x: Entered\n", gettid());
   rc = pthread_mutex_lock(&dataMutex);
   checkResults("pthread_mutex_lock()\n", rc);

   while (retries--) {
      /* The boolean dataPresent value is required for safe use of */
      /* condition variables. If no data is present we wait, other */
      /* wise we process immediately.                              */
      while (!dataPresent) {
         printf("Consumer Thread: Wait for data to be produced\n");
         clock_gettime(CLOCK_REALTIME, &abstime);
         abstime.tv_sec += 30;
         rc = pthread_cond_timedwait(&dataPresentCondition, &dataMutex, &abstime);
         if (rc) {
            printf("Consumer Thread: condwait failed, rc=%d\n",rc);
            pthread_mutex_unlock(&dataMutex);
            exit(1);
         }
      }
      printf("Consumer Thread %.8x: Found data or Notified, "
             "CONSUME IT while holding lock\n",
             gettid());
      /* Typically an application should remove the data from being    */
      /* in the shared structure or Queue, then unlock. Processing     */
      /* of the data does not necessarily require that the lock is held */
      /* Access to shared data goes here */
      --sharedData;
      /* We consumed the last of the data */
      if (sharedData==0) {dataPresent=0;}
      /* Repeat holding the lock. pthread_cond_wait releases it atomically */
   }
   printf("Consumer Thread %.8x: All done\n",gettid());
   rc = pthread_mutex_unlock(&dataMutex);
   checkResults("pthread_mutex_unlock()\n", rc);
   return NULL;
}

int main(int argc, char **argv)
{
   pthread_t             thread[NUMTHREADS];
   int                   rc=0;
   int                   amountOfData=4;
   int                   i;

   printf("Enter Testcase - %s\n", argv[0]);

   printf("Create/start threads\n");
   for (i=0; i <NUMTHREADS; ++i) {
 rc = pthread_create(&thread[i], NULL, theThread, NULL);
      checkResults("pthread_create()\n", rc);
   }

   /* The producer loop */
   while (amountOfData--) {
      printf("Producer: 'Finding' data\n");
      sleep(2*amountOfData);

      rc = pthread_mutex_lock(&dataMutex);   /* Protect shared data and flag  */
      checkResults("pthread_mutex_lock()\n", rc);
      printf("Producer: Make data shared and notify consumer\n");
      ++sharedData;                          /* Add data                      */
      dataPresent=1;                         /* Set boolean predicate         */

      rc = pthread_cond_signal(&dataPresentCondition); /* wake up a consumer  */
      if (rc) {
         pthread_mutex_unlock(&dataMutex);
         printf("Producer: Failed to wake up consumer, rc=%d\n", rc);
         exit(1);
      }

      printf("Producer: Unlock shared data and flag\n");
      rc = pthread_mutex_unlock(&dataMutex);
      checkResults("pthread_mutex_lock()\n",rc);
   }

   printf("Wait for the threads to complete, and release their resources\n");
   for (i=0; i <NUMTHREADS; ++i) {
  rc = pthread_join(thread[i], NULL);
      checkResults("pthread_join()\n", rc);
   }

   printf("Clean up\n");
   rc = pthread_mutex_destroy(&dataMutex);
   rc = pthread_cond_destroy(&dataPresentCondition);
   printf("Main completed\n");
   return 0;
}
