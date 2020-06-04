/* Sync Tracing Client:
 * synctrace.cpp
 *
 * Traces all memory operations and MVEE sync ops to find uninstrumented accesses to
 * synchronization variables (or, at least, instrumented .
 *
 * The runtime options for this client include:
 *   -woc_agent  The libc uses the wall-of-clocks synchronization agent
 */

/* DR headers */
#include "dr_api.h"
#include "drmgr.h"
#include "droption.h"
#include "drsyms.h"
#include "drwrap.h"
#include "hashtable.h"

/* C/C++ headers */
#include <cstdint>
#include <inttypes.h>
#include <sys/types.h>

static droption_t<std::string> log_filename(
    DROPTION_SCOPE_CLIENT, "log_file", "",
    "log file",
    "The log file to which we output.");

static droption_t<bool> woc_agent(
    DROPTION_SCOPE_CLIENT, "woc_agent", true,
    "libc uses wall-of-clocks synchronization agent",
    "The patched libc uses the wall-of-clocks synchronization agent. If it uses one of the other agents, set this option to false.");

file_t log_file;

/* TLS */
typedef struct {
    void *last_sync_address;
    uintptr_t last_sync_ret;
} per_thread_t;
static int tls_idx;

/*================================================================================*/
/* Logging functions                                                              */
/*================================================================================*/
#define MAX_SYM_RESULT 256
static void
print_address(file_t f, app_pc addr)
{
    drsym_info_t sym;
    char name[MAX_SYM_RESULT];
    char file[MAXIMUM_PATH];
    module_data_t *data = dr_lookup_module(addr);
    if (data == NULL) {
        dr_fprintf(f, PFX " ? ??:0\n", addr);
        return;
    }
    sym.struct_size = sizeof(sym);
    sym.name = name;
    sym.name_size = MAX_SYM_RESULT;
    sym.file = file;
    sym.file_size = MAXIMUM_PATH;

    drsym_error_t symres = drsym_lookup_address(data->full_path, addr - data->start, &sym, DRSYM_DEFAULT_FLAGS);
    if (symres == DRSYM_SUCCESS || symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
        const char *modname = dr_module_preferred_name(data);
        if (modname == NULL)
            modname = "<noname>";
        dr_fprintf(f, PFX " %s!%s+" PIFX, addr, modname, sym.name,
                   addr - data->start - sym.start_offs);
        if (symres == DRSYM_ERROR_LINE_NOT_AVAILABLE) {
            dr_fprintf(f, " ??:0\n");
        } else {
            dr_fprintf(f, " %s:%" UINT64_FORMAT_CODE "+" PIFX "\n", sym.file, sym.line,
                       sym.line_offs);
        }
    } else
        dr_fprintf(f, PFX " ? ??:0\n", addr);

    dr_free_module_data(data);
}

/*================================================================================*/
/* Helper functions                                                               */
/*================================================================================*/
static hashtable_t sync_variables;
static hashtable_t uninstrumented_ops;
#define HASH_BITS 13

static bool
is_synchronization_variable(void *address)
{
    return hashtable_lookup(&sync_variables, address) != NULL;
}

static app_pc
get_synchronization_variable_use(void *address)
{
    return (app_pc)hashtable_lookup(&sync_variables, address);
}

/* Returns true if the variable was updated, false if it was not present yet and is now inserted */
static bool
set_synchronization_variable_use(void *address, app_pc ip)
{
    return hashtable_add_replace(&sync_variables, address, ip) != NULL;
}

/* Returns true if the uninstrumented operation was inserted, false if it was already present */
static bool
add_uninstrumented_op(void *ip)
{
    return hashtable_add(&uninstrumented_ops, ip, ip);
}

/*================================================================================*/
/* Instrumentation callbacks                                                      */
/*================================================================================*/

static void
atomic_preop(void *wrapcxt, OUT void **user_data)
{
    /* Definition for the total-order and partial-order synchronization agents:
     *  unsigned char mvee_atomic_preop_internal(unsigned short op_type, void* word_ptr)
     * Definition for the wall-of-clocks synchronization agent:
     *  unsigned char mvee_atomic_preop_internal(volatile void* word_ptr)
     */
    void* address = drwrap_get_arg(wrapcxt, woc_agent.get_value() ? 0 : 1);
    app_pc ret = drwrap_get_retaddr(wrapcxt);

    set_synchronization_variable_use(address, ret);

    per_thread_t *data = (per_thread_t*)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);

    /* Check whether the previous PreOp was matched by a PostOp */
    if (data->last_sync_address)
    {
        dr_fprintf(STDERR, "Probably unmatched PreOp!\n");
        DR_ASSERT(false);
    }

    /* Set TLS variables */
    data->last_sync_address = address;
    data->last_sync_ret = (uintptr_t)ret;
}

static void
atomic_postop(void *wrapcxt, OUT void **user_data)
{
    /* Definition for all synchronization agents:
     *  void mvee_atomic_postop_internal(unsigned char preop_result)
     */

    per_thread_t *data = (per_thread_t*)drmgr_get_tls_field(dr_get_current_drcontext(), tls_idx);

    /* Check whether the PostOp was preceded by a PreOp (by checking whether the return addresses are close) */
    uintptr_t current_ret = (uintptr_t)drwrap_get_retaddr(wrapcxt);
    if ((current_ret - data->last_sync_ret) > 0x50)
    {
        dr_fprintf(STDERR, "Probably unmatched PostOp!\n");
        dr_fprintf(STDERR, "Previous PreOp return address: ");
        print_address(STDERR, (app_pc)data->last_sync_ret);
        dr_fprintf(STDERR, "Current PostOp return address: ");
        print_address(STDERR, (app_pc)current_ret);
        DR_ASSERT(false);
    }

    /* Unset TLS variables */
    data->last_sync_address = NULL;
    data->last_sync_ret = 0;
}

static void
memop(app_pc ip)
{
    /* Get all of the context */
    dr_mcontext_t mcontext = {
        sizeof(mcontext),
        DR_MC_ALL,
    };
    void *drcontext = dr_get_current_drcontext();
    dr_get_mcontext(drcontext, &mcontext);

    /* Decode the instruction */
    instr_t* instr = instr_create(drcontext);
    decode(drcontext, ip, instr);
    uint op_size = instr_memory_reference_size(instr);

    /* Compute the address for every operand, until we run out */
    app_pc address;
    bool write;
    for(uint iii = 0; instr_compute_address_ex(instr, &mcontext, iii, &address, &write); iii++)
    {
        /* Check alignment */
        bool aligned;
        switch (op_size)
        {
            case 1:
                aligned = true;
                break;
            case 2:
            case 4:
            case 8:
                aligned = ((uintptr_t)address % op_size) == 0;
                break;
            default:
                aligned = false;
                break;
        }

        /* Is this an aligned access to a synchronization variable? */
        if (aligned && is_synchronization_variable(address))
        {
            per_thread_t *data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_idx);

            /* Does the access lack instrumentation? */
            if (data->last_sync_address != address)
            {
                /* Cache the result, don't log if it's a duplicate */
                if (add_uninstrumented_op(ip))
                {
                    dr_fprintf(log_file, "Uninstrumented %s of synchronization variable with address " PFX "\n", write ? "write" : "read", address);
                    dr_fprintf(log_file, "The previous instrumented access to this variable was at: ");
                    print_address(log_file, get_synchronization_variable_use(address));
                    dr_fprintf(log_file, "This UNinstrumented access occured at: ");
                    print_address(log_file, ip);
                    dr_fprintf(log_file, "\n");
                    dr_flush_file(log_file);
                }
            }
        }
    }

    /* Cleanup */
    instr_destroy(drcontext, instr);
}

/*================================================================================*/
/* Event callbacks                                                                */
/*================================================================================*/

static void
module_load_event(void *drcontext, const module_data_t *mod, bool loaded)
{
    app_pc towrap = (app_pc)dr_get_proc_address(mod->handle, "mvee_atomic_preop_internal");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, atomic_preop, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap mvee_atomic_preop_internal\n");
            DR_ASSERT(ok);
        }
    }

    towrap = (app_pc)dr_get_proc_address(mod->handle, "mvee_atomic_postop_internal");
    if (towrap != NULL) {
        bool ok = drwrap_wrap(towrap, atomic_postop, NULL);
        if (!ok) {
            dr_fprintf(STDERR, "Couldn’t wrap mvee_atomic_postop_internal\n");
            DR_ASSERT(ok);
        }
    }
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    /* Ignore meta-instructions */
    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    if (instr_reads_memory(instr) || instr_writes_memory(instr))
    {
        dr_insert_clean_call(drcontext, bb, instr, (void *)memop,
                                 false /* don't save fp state */,
                                 1 /* 1 args for memop() */, 
                                 OPND_CREATE_INTPTR(instr_get_app_pc(instr)));
    }


    return DR_EMIT_DEFAULT;
}
static void
event_thread_init(void *drcontext)
{
    /* TLS */
    per_thread_t *data = (per_thread_t*)dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    drmgr_set_tls_field(drcontext, tls_idx, data);
    data->last_sync_address = 0;
    data->last_sync_ret = 0;
}

static void
event_thread_exit(void *drcontext)
{
    /* TLS */
    per_thread_t *data;
    data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_idx);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void
event_exit(void)
{
    /* Unregister events */
    drmgr_unregister_tls_field(tls_idx);
    drmgr_unregister_bb_insertion_event(event_app_instruction);
    drmgr_unregister_thread_init_event(event_thread_init);
    drmgr_unregister_thread_exit_event(event_thread_exit);
    drmgr_unregister_module_load_event(module_load_event);

    hashtable_delete(&sync_variables);
    hashtable_delete(&uninstrumented_ops);
    drwrap_exit();
    drsym_exit();
    drmgr_exit();
}

/*================================================================================*/
/* Main                                                                           */
/*================================================================================*/

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("ReMon Dynamorio client 'SyncTrace'", "https://github.com/ku-leuven-msec/ReMon");

    /* Options */
    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, NULL, NULL))
        DR_ASSERT(false);

    if (!log_filename.get_value().empty())
    {
        log_file = dr_open_file(log_filename.get_value().c_str(), DR_FILE_WRITE_OVERWRITE);
        DR_ASSERT(log_file != INVALID_FILE);
    }
    else
      log_file = STDERR;

    /* Initialization of extensions */
    drmgr_init();
    if (drsym_init(0) != DRSYM_SUCCESS)
        dr_log(NULL, DR_LOG_ALL, 1, "WARNING: unable to initialize symbol translation\n");
    drwrap_init();

    /* register events */
    drmgr_register_module_load_event(module_load_event);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    drmgr_register_bb_instrumentation_event(NULL, event_app_instruction, NULL);
    dr_register_exit_event(event_exit);

    /* TLS initialization */
    tls_idx = drmgr_register_tls_field();
    DR_ASSERT(tls_idx != -1);

    hashtable_init_ex(&sync_variables, HASH_BITS, HASH_INTPTR, false /*!strdup*/,
            true /*synchronization is internal*/, NULL, NULL, NULL);
    hashtable_init_ex(&uninstrumented_ops, HASH_BITS, HASH_INTPTR, false /*!strdup*/,
            true /*synchronization is internal*/, NULL, NULL, NULL);

    dr_log(NULL, DR_LOG_ALL, 1, "Client 'SyncTrace' initializing\n");
}
