#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

char* mvee_log_read_from_proc_pipe(const char* proc, int* output_length)
{
    char  tmp_buf[1024];
    char* result        = (char*)malloc(2);
    int   result_length = 2;
    int   result_pos    = 0;
    FILE* fp            = popen(proc, "r");

    if (!fp || feof(fp))
    {
        //      warnf("ERROR: couldn't create procpipe: %s\n", proc);
        if (output_length)
            *output_length = 0;
        return NULL;
    }

    while (!feof(fp))
    {
        int read = fread(tmp_buf, 1, 1024, fp);

        if (read > result_length - result_pos - 2)
        {
            result        = (char*)realloc(result, read + result_pos + 2);
            result_length = read + result_pos + 2;
        }

        memcpy(result + result_pos, tmp_buf, read);
        result_pos += read;
    }

    pclose(fp);
    if (output_length)
        *output_length = result_pos;
    result[result_pos] = '\0';
    return result;
}

int  main(int argc, char** argv)
{
    char* pid = mvee_log_read_from_proc_pipe("ps ux | grep \"\\" MVEE " \" | grep -v grep | sed -e 's/  */ /g' | cut -d' ' -f2", NULL);

    int   i;
    for (i = 0; i < strlen(pid); ++i)
        if (pid[i] == 10 || pid[i] == 13)
            pid[i] = 0;
    printf("PID: %s (%zu)\n", pid, strlen(pid));
    if (strlen(pid) > 0)
    {
        int _pid = atoi(pid);

        //      char cmd[500];
        //sprintf(cmd, "kill -int %d\n", _pid);
        //      sprintf(cmd, "kill -quit %d\n", _pid);
        //      mvee_log_read_from_proc_pipe(cmd, NULL);
		syscall(__NR_tgkill, _pid, _pid, SIGUSR2);
    }

    return 0;
}
