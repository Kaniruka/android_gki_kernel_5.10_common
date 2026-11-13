#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the real bridge bodies with controlled backends; no device needed.

Run: python3 tools/testing/selftests/selinux/ksu_bridge_test.py
This checks routing and setprocattr's live-SID/error contract, not SELinux
policy computation, CFI linkage, or target-device behavior.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]


def body(source, name):
    text = (ROOT / source).read_text()
    match = re.search(r"\b" + re.escape(name) + r"\([^;]*?\)\s*\{", text)
    if not match:
        raise AssertionError(f"function not found: {name}")
    start = text.index("{", match.start())
    depth = 1
    end = start + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


wrappers = "\n".join([
    "static ssize_t handle_sel_write_context(struct file *file, char *buf, size_t size) "
    + body("security/selinux/selinuxfs.c", "handle_sel_write_context"),
    "static ssize_t handle_sel_write_access(struct file *file, char *buf, size_t size) "
    + body("security/selinux/selinuxfs.c", "handle_sel_write_access"),
    "static int handle_selinux_setprocattr(const char *name, void *value, size_t size) "
    + body("security/selinux/hooks.c", "handle_selinux_setprocattr"),
])
# Under SUSFS compatibility the real body must compile without any original
# hook pointer or orig-context callback. Its only fallback is in the wrapper.
setproc = "int my_setprocattr(const char *name, void *value, size_t size) " + body(
    "KernelSU/kernel/feature/selinux_hide.c", "ksu_handle_selinux_setprocattr")

lifecycle = "\n".join(signature + body(
    "KernelSU/kernel/feature/selinux_hide.c", name) for signature, name in [
        ("bool ksu_selinux_hide_begin_query(void) ", "ksu_selinux_hide_begin_query"),
        ("void ksu_selinux_hide_end_query(void) ", "ksu_selinux_hide_end_query"),
        ("static int selinux_hide_feature_set(uint64_t value) ", "selinux_hide_feature_set"),
        ("void ksu_selinux_hide_drop_backup_if_unused(void) ", "ksu_selinux_hide_drop_backup_if_unused"),
    ])

harness = r"""
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sched.h>
#define KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5,10,240)
#define likely(x) (x)
#define GFP_KERNEL 0
#define SECSID_NULL 0
#define SECCLASS_PROCESS 1
#define PROCESS__SETCURRENT 1
#define PROCESS__DYNTRANSITION 2
#define PROCESS__PTRACE 3
typedef uint32_t u32;
struct file { int unused; };
struct uid { unsigned val; };
static struct uid uid;
static struct uid current_uid(void) { return uid; }
static bool ksu_selinux_hide_running;
static struct file file;
static char buffer[64];
static int called, result, native_calls;
static bool block_query, entered, release_query;
static pthread_mutex_t signal_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t signal_cond = PTHREAD_COND_INITIALIZER;
static void query_gate(void) {
    assert(pthread_mutex_lock(&signal_lock)==0);
    if (block_query) {
        entered=true; pthread_cond_broadcast(&signal_cond);
        while (!release_query) pthread_cond_wait(&signal_cond, &signal_lock);
    }
    assert(pthread_mutex_unlock(&signal_lock)==0);
}
static void args(struct file *f, char *b, size_t n) {
    assert(f == &file && b == buffer && n == sizeof(buffer));
}
static ssize_t my_write_context(struct file *f, char *b, size_t n) {
    args(f,b,n); query_gate(); called = 1; return result;
}
static ssize_t my_write_access(struct file *f, char *b, size_t n) {
    args(f,b,n); called = 2; return result;
}
static ssize_t sel_write_context(struct file *f, char *b, size_t n) {
    args(f,b,n); called = 3; return result;
}
static ssize_t sel_write_access(struct file *f, char *b, size_t n) {
    args(f,b,n); called = 4; return result;
}
static int selinux_setprocattr(const char *n, void *v, size_t s) {
    assert(n && v == buffer && s == sizeof(buffer));
    native_calls++; return result;
}
struct ksu_task_security_struct { u32 sid; };
struct cred { struct ksu_task_security_struct sec; };
static struct cred cred;
static int perm_error, backup_error, live_error, alloc_fail, committed, aborted;
static u32 transitioned;
struct snapshot { void *sidtab; };
static struct snapshot snapshot;
static struct snapshot *backup_sepolicy = &snapshot;
static bool ksu_selinux_hide_enabled;
static pthread_mutex_t selinux_hide_mutex = PTHREAD_MUTEX_INITIALIZER;
static _Thread_local bool dropping;
static atomic_bool attempted, finished, freed;
static void mutex_lock(pthread_mutex_t *lock) {
    if (dropping) atomic_store(&attempted, true);
    assert(pthread_mutex_lock(lock)==0);
}
static void mutex_unlock(pthread_mutex_t *lock) { assert(pthread_mutex_unlock(lock)==0); }
#define pr_info(...) ((void)0)
static int ksu_selinux_hide_enable(void) { return backup_sepolicy ? 0 : -EAGAIN; }
static void ksu_selinux_hide_disable(void) {}
static void sidtab_destroy(void *p) { (void)p; }
static void kfree(void *p) { (void)p; }
static void ksu_destroy_sepolicy(struct snapshot *p) {
    assert(p == &snapshot); atomic_store(&freed, true);
}
static u32 current_sid(void) { return 11; }
static int ksu_avc_has_perm_compat(u32 a, u32 b, int c, int p, void *v) {
    (void)a; (void)c; (void)v;
    if (p == PROCESS__DYNTRANSITION) transitioned = b;
    return perm_error;
}
static int security_context_to_sid_with_policy(void *policy, void *v, size_t n,
        u32 *sid, u32 def, int gfp, u32 *live_sid, int *live_rc) {
    assert(policy == backup_sepolicy && v == buffer && n == sizeof(buffer));
    (void)def; (void)gfp;
    *sid = 123; *live_sid = 456; *live_rc = live_error;
    return backup_error;
}
static struct cred *prepare_creds(void) { return alloc_fail ? NULL : &cred; }
static struct ksu_task_security_struct *selinux_cred(struct cred *c) { return &c->sec; }
static bool current_is_single_threaded(void) { return true; }
static int ksu_security_bounded_transition_compat(u32 a, u32 b) {
    (void)a; (void)b; return 0;
}
static u32 ptrace_parent_sid(void) { return 0; }
static void commit_creds(struct cred *c) { assert(c == &cred); committed++; }
static void abort_creds(struct cred *c) { assert(c == &cred); aborted++; }
"""
main = r"""
static void *query_worker(void *p) {
    (void)p;
    assert(handle_sel_write_context(&file,buffer,sizeof(buffer))==result);
    return NULL;
}
static void *drop_worker(void *p) {
    (void)p; dropping=true;
    assert(selinux_hide_feature_set(0)==0);
    ksu_selinux_hide_drop_backup_if_unused();
    atomic_store(&finished, true);
    return NULL;
}
static void concurrent_lifetime(void) {
    pthread_t query, drop;
    backup_sepolicy=&snapshot; ksu_selinux_hide_running=true;
    uid.val=90000; result=17; block_query=true; called=0;
    assert(pthread_create(&query,NULL,query_worker,NULL)==0);
    pthread_mutex_lock(&signal_lock);
    while (!entered) pthread_cond_wait(&signal_cond,&signal_lock);
    pthread_mutex_unlock(&signal_lock);
    assert(pthread_create(&drop,NULL,drop_worker,NULL)==0);
    while (!atomic_load(&attempted)) sched_yield();
    /* The real query owns the same mutex needed by disable and snapshot drop. */
    assert(!atomic_load(&freed) && !atomic_load(&finished));
    assert(pthread_mutex_trylock(&selinux_hide_mutex)==EBUSY);
    pthread_mutex_lock(&signal_lock); release_query=true;
    pthread_cond_broadcast(&signal_cond); pthread_mutex_unlock(&signal_lock);
    assert(pthread_join(query,NULL)==0 && pthread_join(drop,NULL)==0);
    assert(called==1 && atomic_load(&freed) && backup_sepolicy==NULL);
    /* Disable/drop won the race: no query may dereference the null snapshot. */
    block_query=false; called=0;
    assert(handle_sel_write_context(&file,buffer,sizeof(buffer))==result && called==3);
    assert(handle_sel_write_access(&file,buffer,sizeof(buffer))==result && called==4);
    native_calls=0;
    assert(handle_selinux_setprocattr("current",buffer,sizeof(buffer))==result);
    assert(native_calls==1);
    /* Also exercise false-begin unlock for an unavailable backup. */
    ksu_selinux_hide_running=true;
    assert(!ksu_selinux_hide_begin_query());
    assert(pthread_mutex_trylock(&selinux_hide_mutex)==0);
    pthread_mutex_unlock(&selinux_hide_mutex);
}
int main(void) {
    unsigned ids[] = {0, 9999, 10000, 90000, 99000, 110000};
    const char *names[] = {"current", "exec", "fscreate", "keycreate", "sockcreate", "invalid"};
    int results[] = {17, -EINVAL, -ENOMEM};
    memset(buffer, 'x', sizeof(buffer));
    for (size_t i=0; i<sizeof(ids)/sizeof(ids[0]); i++)
    for (int enabled=0; enabled<2; enabled++)
    for (size_t j=0; j<sizeof(results)/sizeof(results[0]); j++) {
        uid.val=ids[i]; ksu_selinux_hide_running=enabled; result=results[j];
        bool hide=ids[i]>=10000 && enabled;
        called=0; assert(handle_sel_write_context(&file,buffer,sizeof(buffer))==result);
        assert(called==(hide ? 1 : 3));
        called=0; assert(handle_sel_write_access(&file,buffer,sizeof(buffer))==result);
        assert(called==(hide ? 2 : 4));
        for (size_t k=0; k<sizeof(names)/sizeof(names[0]); k++) {
            native_calls=committed=aborted=0; transitioned=0;
            perm_error=backup_error=live_error=alloc_fail=0;
            int rc=handle_selinux_setprocattr(names[k],buffer,sizeof(buffer));
            if (hide && k==0) {
                assert(rc==(int)sizeof(buffer) && committed==1 && native_calls==0);
                assert(cred.sec.sid==456 && transitioned==456 && aborted==0);
            } else assert(rc==result && native_calls==1 && committed==0);
        }
    }
    uid.val=90000; ksu_selinux_hide_running=true;
    perm_error=-EACCES;
    assert(handle_selinux_setprocattr("current",buffer,sizeof(buffer))==-EACCES);
    perm_error=0; backup_error=-EINVAL;
    assert(handle_selinux_setprocattr("current",buffer,sizeof(buffer))==-EINVAL);
    backup_error=0; live_error=-ESTALE;
    assert(handle_selinux_setprocattr("current",buffer,sizeof(buffer))==-ESTALE);
    live_error=0; alloc_fail=1;
    assert(handle_selinux_setprocattr("current",buffer,sizeof(buffer))==-ENOMEM);
    concurrent_lifetime();
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix="ksu-bridge-") as tmp:
    source = Path(tmp) / "bridge.c"
    binary = Path(tmp) / "bridge"
    source.write_text(harness + lifecycle + "\n" + setproc + "\n" + wrappers + main)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra", "-Wno-unused-parameter",
                    "-Werror", "-pthread", str(source), "-o", str(binary)], check=True, timeout=30)
    subprocess.run([str(binary)], check=True, timeout=15)
print("PASS: real bridge routing, native fallbacks, errors, live-SID transitions, and concurrent snapshot lifetime")
