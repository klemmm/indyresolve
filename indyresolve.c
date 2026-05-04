#include "dr_api.h"
#include "drutil.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

#include "include/uthash.h"

#define MAX_MODULES 1024

/* ---------------- modules ---------------- */

static int modules_count = 0;
static module_data_t *modules[MAX_MODULES];
static file_t dbs[MAX_MODULES];
static void *module_lock;

/* ---------------- TLS ---------------- */

typedef struct {
    struct entry_t *table;
} tls_t;

/* ---------------- edge hash ---------------- */

typedef struct {
    app_pc src;
    app_pc dst;
} edge_t;

typedef struct entry_t {
    edge_t key;
    UT_hash_handle hh;
} entry_t;

/* ---------------- module tracking ---------------- */

static void event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    static char dbname[1024];

    if (!strcmp(info->full_path, "[vdso]"))
        return;

    dr_mutex_lock(module_lock);
    if (modules_count >= MAX_MODULES) {
        printf("warning: ignoring module %s\n", info->full_path);
        return;
    }

    modules[modules_count] = dr_copy_module_data(info);

    snprintf(dbname, sizeof(dbname), "%s.json", info->full_path);
    dbs[modules_count] = dr_open_file(dbname, DR_FILE_WRITE_APPEND | DR_FILE_ALLOW_LARGE);
    modules_count++;
    dr_mutex_unlock(module_lock);
}

static int find_module_containing_addr(app_pc addr) {
    for (int i = 0; i < modules_count; i++) {
        if (addr >= modules[i]->start && addr < modules[i]->end) {
            return i;
        }
    }
    return -1;
}

/* ---------------- TLS helpers ---------------- */

static inline tls_t *get_tls(void *drcontext)
{
    return (tls_t *)dr_get_tls_field(drcontext);
}

/* ---------------- clean call ---------------- */

static inline void record_call(app_pc addr, app_pc dest) {
    void *drcontext = dr_get_current_drcontext();

    tls_t *tls = get_tls(drcontext);
    if (tls == NULL)
        return;


    edge_t key = {0};
    key.src = addr;
    key.dst = dest;

    entry_t *e = NULL;

    HASH_FIND(hh, tls->table, &key, sizeof(edge_t), e);

    if (e == NULL) {
        e = dr_thread_alloc(drcontext, sizeof(entry_t));
        memset(e, 0, sizeof(entry_t));

        e->key = key;

        HASH_ADD(hh, tls->table, key, sizeof(edge_t), e);
    }
}

static void handle_indirect_call_reg(app_pc addr, reg_t val)
{
    app_pc dest = (app_pc)val;
    record_call(addr, dest);
}

static void handle_indirect_call_mem(app_pc addr, reg_t val)
{
    app_pc indir_addr = (app_pc)val;
    app_pc dest;
    if (dr_safe_read(indir_addr, sizeof(app_pc), &dest, NULL)) {
        record_call(addr, dest);
    }
}


/* ---------------- instrumentation ---------------- */

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating)
{
    for (instr_t *i = instrlist_first(bb); i != NULL; i = instr_get_next(i)) {

        if (instr_is_mbr(i) && !instr_is_return(i)) {
            app_pc addr = instr_get_app_pc(i);

            opnd_t target = instr_get_target(i);

            if (opnd_is_reg(target)) {
                app_pc addr = instr_get_app_pc(i);
                reg_id_t reg = opnd_get_reg(target);

                dr_insert_clean_call(
                    drcontext, bb, i,
                    (void *)handle_indirect_call_reg,
                    false, 2,
                    OPND_CREATE_INTPTR(addr),
                    opnd_create_reg(reg));
            } else if (opnd_is_memory_reference(target)) {
                reg_id_t scratch = DR_REG_RAX;

                dr_save_reg(drcontext, bb, i, scratch, SPILL_SLOT_1);

				drutil_insert_get_mem_addr(
					drcontext,
					bb,
					i,
					target,
					scratch,
					DR_REG_NULL);
				dr_insert_clean_call(
					drcontext, bb, i,
					(void *)handle_indirect_call_mem,
					false, 2,
					OPND_CREATE_INTPTR(addr),
					opnd_create_reg(scratch));
                dr_restore_reg(drcontext, bb, i, scratch, SPILL_SLOT_1);

            }
        }
    }

    return DR_EMIT_DEFAULT;
}

/* ---------------- thread lifecycle ---------------- */

static void thread_init(void *drcontext)
{

    tls_t *tls = dr_thread_alloc(drcontext, sizeof(tls_t));
    memset(tls, 0, sizeof(tls_t));

    dr_set_tls_field(drcontext, tls);
}

static void thread_exit(void *drcontext)
{

    tls_t *tls = get_tls(drcontext);
    if (tls == NULL)
        return;

    entry_t *e, *tmp;

    /* We do not bother about inter-thread edge deduplication (only intra-thread) */
    HASH_ITER(hh, tls->table, e, tmp) {
        dr_mutex_lock(module_lock);
        int source_mod_idx = find_module_containing_addr(e->key.src);
        int target_mod_idx = find_module_containing_addr(e->key.dst);

        if (source_mod_idx != -1 && target_mod_idx != -1) {
            const module_data_t *source_mod = modules[source_mod_idx];
            const module_data_t *target_mod = modules[target_mod_idx];

            char buf[1024];
            int size;
            if (source_mod_idx == target_mod_idx) {
                /* special "null" value represents intra-module call */
                size = snprintf(buf, sizeof(buf), "[%lu, null, %lu]\n", e->key.src - source_mod->start, e->key.dst - target_mod->start);
            } else {
                size = snprintf(buf, sizeof(buf), "[%lu, \"%s\", %lu]\n", e->key.src - source_mod->start, target_mod->full_path, e->key.dst - target_mod->start);
            }

            if (size >= sizeof(buf)) abort(); /* should never happen */

            /* Let the kernel handle atomic file write */
	    if (dbs[source_mod_idx] != INVALID_FILE)
		    dr_write_file(dbs[source_mod_idx], buf, size);

        }
        dr_mutex_unlock(module_lock);

        HASH_DEL(tls->table, e);
        dr_thread_free(drcontext, e, sizeof(entry_t));
    }

    dr_thread_free(drcontext, tls, sizeof(tls_t));
}

/* ---------------- exit ---------------- */

static void event_exit(void)
{
    for (int i = 0; i < modules_count; i++) {
        if (dbs[i] != INVALID_FILE)
            dr_close_file(dbs[i]);
        dr_free_module_data(modules[i]);
    }

}

/* ---------------- main ---------------- */

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    dr_set_client_name("Indyresolve Client", "");
    module_lock = dr_mutex_create();

    dr_register_thread_init_event(thread_init);
    dr_register_thread_exit_event(thread_exit);
    dr_register_exit_event(event_exit);

    dr_register_bb_event(event_bb_analysis);
    dr_register_module_load_event(event_module_load);
}
