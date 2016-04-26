/*
 * GHent University Multi-Variant Execution Environment (GHUMVEE)
 *
 * This source file is distributed under the terms and conditions 
 * found in GHUMVEELICENSE.txt.
 */

/*=============================================================================
    This program adds 1 million elements to a g_cache which internally uses a
    hash table. If "monitor" is supplied as the first argument, the hash
    function executes a fake syscall which lets the monitor synchronize the
    calculated hash value among the children.

    This program can be used to compare the performance with and without hash
    function interception and hash value synchronization.
=============================================================================*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>

#include "glib.h"

#include "../gtk_interposer/gtk_interposer.h"

static int monitored = 0;

gpointer gc_new(gpointer value)
{
    return (gpointer)malloc(1);
}

void gc_destroy(gpointer value)
{
    free(value);
}

gpointer gc_key_dup(gpointer key)
{
    return key;
}

guint gc_monitor_hash(gconstpointer key)
{
    guint hash = g_direct_hash(key);
    syscall(MVEE_GTK_FAKE_SYSCALL, &hash);
    return hash;
}

int main(int argc, char *argv[])
{
    int i;
    GCache* cache;
    GHashFunc hashfunc;
    monitored = (argc > 1 && strcasecmp(argv[1], "monitor") == 0);
    if (monitored)
        hashfunc = gc_monitor_hash;
    else
        hashfunc = g_direct_hash;
    cache = g_cache_new(gc_new, gc_destroy, gc_key_dup, gc_destroy,
                                hashfunc, hashfunc, g_direct_equal);
    for (i = 0; i < 1000000; ++i)
        g_cache_insert(cache, malloc(1));
    g_cache_destroy(cache);
    return 0;
}
