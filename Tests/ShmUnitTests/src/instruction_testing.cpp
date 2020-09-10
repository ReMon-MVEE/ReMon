//
// Created by jonas on 05.06.20.
//

#include "instruction_testing.h"
#include "stats.h"


// =====================================================================================================================
//      logging implementation
// =====================================================================================================================
void            testing_general::setup_log                          ()
{
#ifdef LOG_FILE
    testing_general::log_file = fopen(LOG_FILE, "w");
#endif
}

void            testing_general::log                                (const char* format, ...)
{
#ifdef LOG
    va_list va;
    va_start(va, format);
    printf(" > ");
    vfprintf(stdout, format, va);
    va_end(va);
#endif

#ifdef LOG_FILE
    if (testing_general::log_file)
    {
        va_list file_va;
        va_start(file_va, format);
        fprintf(testing_general::log_file, " > ");
        vfprintf(testing_general::log_file, format, file_va);
        va_end(file_va);
    }
#endif
}


void            testing_general::log_flush                          ()
{
#ifdef LOG
    fflush(stdout);
#endif

#ifdef LOG_FILE
    if (testing_general::log_file)
        fflush(testing_general::log_file);
#endif
}


void            testing_general::log_spacer                         ()
{
#ifdef LOG
    printf("\n");
#endif

#ifdef LOG_FILE
    if (testing_general::log_file)
        fprintf(testing_general::log_file, "\n");
    fflush(testing_general::log_file);
#endif
}


void            testing_general::log_stats                          (double duration)
{
    failed* entry;
#ifdef LOG
    printf(" > stats =====================================\n");
    printf("\truns:            %d - %.2f ms\n", stats::run, duration);
    printf("\tsuccessful runs: %d - %.2f%%\n", stats::success,
            ((float) stats::success / (float) stats::run) * 100);
    printf("\tfailed:          %d - %.2f%%\n", stats::run - stats::success,
            ((float) (stats::run - stats::success) / (float) stats::run) * 100);
    entry = stats::failed_queue;
    while (entry)
    {
        printf("\t\t* %s\n", entry->message);
        entry = entry->next;
    }
    printf(" > stats =====================================\n");
#endif

#ifdef LOG_FILE
    if (testing_general::log_file)
    {
        fprintf(testing_general::log_file, " > stats =====================================\n");
        fprintf(testing_general::log_file, "\truns:            %d - %.2f ms\n", stats::run, duration);
        fprintf(testing_general::log_file, "\tsuccessful runs: %d - %.2f%%\n",
                stats::success, ((float) stats::success / (float) stats::run) * 100);
        fprintf(testing_general::log_file, "\tfailed:          %d - %.2f%%\n",
                stats::run - stats::success, ((float) (stats::run - stats::success) / (float) stats::run) * 100);
        entry = stats::failed_queue;
        while (entry)
        {
            fprintf(testing_general::log_file, "\t\t* %s\n", entry->message);
            entry = entry->next;
        }
        fprintf(testing_general::log_file, " > stats =====================================\n");
    }
#endif

    while (stats::failed_queue)
    {
        free(stats::failed_queue->message);
        entry = stats::failed_queue;
        stats::failed_queue = stats::failed_queue->next;
        free(entry);
    }
}


void            testing_general::log_buffer                              (const __uint8_t* buffer, unsigned int size)
{
    for (int i = size - 1; i >= 0; i--)
    {
#ifdef LOG
        printf("%s%llx ", (unsigned long long) buffer[i] > 0xf ? "0x" : "0x0", (unsigned long long) buffer[i] & 0xffu);
#endif

#ifdef LOG_FILE
        if (testing_general::log_file)
            fprintf(testing_general::log_file, "%s%llx ", buffer[i] > 0xf ? "0x" : "0x0",
                    (unsigned long long) buffer[i] & 0xffu);
#endif
    }
    log_spacer();
}


void            testing_general::terminate_log                      ()
{
    testing_general::log("done.\n\n");
#ifdef LOG
    fflush(stdout);
#endif
#ifdef LOG_FILE
    if (testing_general::log_file)
    {
        fflush(testing_general::log_file);
        fclose(testing_general::log_file);
    }
#endif
}


// =====================================================================================================================
//      testing aid implementation
// =====================================================================================================================
int             testing_aid::open_shared_memory                   (void** shared_mapping, void** shared_sink_mapping)
{
#ifdef MEMFD
    int shared_fd = memfd_create(SHARED_FILE, O_RDWR);
    int shared_sink_fd = memfd_create(SHARED_SINK, O_RDWR);
#else
    int shared_fd = open(SHARED_FILE, O_RDONLY);
    int shared_sink_fd = open(SHARED_SINK, O_RDWR);
#endif
    if (shared_fd < 0)
    {
        printf("could not open shared file...\n");
        if (shared_sink_fd >= 0)
            close(shared_sink_fd);
        else
            printf("could not open shared sink file...\n");
        return -1;
    }
    if (shared_sink_fd < 0)
    {
        printf("could not open shared sink file...\n");
        if (shared_fd >= 0)
            close(shared_fd);
        else
            printf("could not open shared file...\n");
        return -1;
    }

#ifdef MEMFD
    ftruncate(shared_fd, SHARED_SIZE);
    ftruncate(shared_sink_fd, SHARED_SIZE);
#endif


    if (!shared_mapping || !shared_sink_mapping)
    {
        printf("null pointers passed\n\tshared mapping: %p\n\tshared sink: %p\n",
               shared_mapping, shared_sink_mapping);
        close(shared_fd);
        close(shared_sink_fd);
        return -1;
    }


    *shared_mapping = mmap(nullptr, SHARED_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, shared_fd, 0);
    if (*shared_mapping == MAP_FAILED)
    {
        printf("mapping shared file failed | errno: %d\n", errno);
        close(shared_fd);
        close(shared_sink_fd);
        return -1;
    }

    *shared_sink_mapping = mmap(nullptr, SHARED_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED,
            shared_sink_fd, 0);
    if (*shared_sink_mapping == MAP_FAILED)
    {
        printf("mapping shared file failed | errno: %d\n", errno);
        close(shared_fd);
        close(shared_sink_fd);
        munmap(*shared_mapping, SHARED_SIZE);
        return -1;
    }


    // return ok
    return 0;
}


int             testing_aid::compare_buffers                        (const __uint8_t* first, const __uint8_t* second,
                                                                     unsigned int size)
{
    for (unsigned int i = 0; i < size; i++)
        if (first[i] != second[i])
            return -1;
    // ok
    return 0;
}


void            testing_aid::clear_buffer                           (__uint8_t* buffer, unsigned int size)
{
    for (unsigned int i = 0; i < size; i++)
        buffer[i] = 0x00;
}
