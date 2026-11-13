#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise actual BakaSU parser/helper bodies with counted policy backends.
Run with python3; no kernel build or device access required.
The stubs check control flow and lifetime, not full SELinux MLS semantics.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
text = (ROOT / "KernelSU/kernel/feature/selinux_hide.c").read_text()

def function(name, declaration=None):
    pattern = r"\b" + name + r"\([^;]*?\)\s*\{"
    match = re.search(pattern, text)
    if declaration:
        match = re.search(r"__maybe_static int " + name + r"\(", text)
    assert match, name
    start = text.index("{", match.start())
    depth, end = 1, start + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    prefix = declaration if declaration else "static int " + text[match.start():start]
    return prefix + text[start:end]

parser = function("string_to_context_struct")
helper = function("security_context_to_sid_with_policy", "static int security_context_to_sid_with_policy(struct selinux_policy *policy, const char *scontext, u32 scontext_len, u32 *sid, u32 def_sid, gfp_t gfp_flags, u32 *orig_sid_p, int *orig_rc_p) ")

# The prototype has compatibility preprocessor branches, so take its body
# after the implementation marker and normalize only the declaration.
start = text.index("int __nocfi ksu_handle_selinux_setprocattr(")
proc_text = text[start:]
proc_start = proc_text.index("{")
proc_depth, proc_end = 1, proc_start + 1
while proc_depth:
    proc_depth += (proc_text[proc_end] == "{") - (proc_text[proc_end] == "}")
    proc_end += 1
proc = "static int my_setprocattr(const char *name, void *value, size_t size) " + proc_text[proc_start:proc_end]

harness = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#define LINUX_VERSION_CODE KERNEL_VERSION(5,10,240)
#define SECSID_NULL 0
#define KSU_COMPAT_HAS_SUSFS_FEATURE_SELINUX_HIDE
#define GFP_KERNEL 0
#define SECCLASS_PROCESS 1
#define PROCESS__SETCURRENT 1
#define PROCESS__DYNTRANSITION 2
#define PROCESS__PTRACE 3
#define rcu_dereference(p) (p)
typedef uint32_t u32;
typedef int gfp_t;
struct role_datum { u32 value; };
struct user_datum { u32 value; };
struct type_datum { u32 value; bool attribute; };
struct symtab { int live, kind; };
struct policydb { struct symtab p_users, p_roles, p_types; int live; };
struct sidtab { int live; };
struct selinux_policy { struct policydb policydb; struct sidtab *sidtab; };
struct context { u32 user, role, type; bool owned; };
static struct sidtab bs={0}, ls={1};
static struct selinux_policy backup={{{0,0},{0,1},{0,2},0},&bs};
static struct selinux_policy live={{{1,0},{1,1},{1,2},1},&ls};
static struct { struct selinux_policy *policy; } selinux_state={&live};
static int copies, outstanding, live_work, insertions[2], rcu_depth, contexts;
static int missing_live, invalid_policy, sid_error[2], mls_error[2], fail_copy;
static void rcu_read_lock(void) { assert(rcu_depth++==0); }
static void rcu_read_unlock(void) { assert(--rcu_depth==0); }
static void *kmemdup_nul(const void *p, size_t n, int flags) {
    (void)flags; assert(rcu_depth==0); copies++;
    if (copies==fail_copy) return NULL;
    char *out=malloc(n+1); assert(out); memcpy(out,p,n); out[n]=0;
    outstanding++; return out;
}
static void kfree(void *p) { if(p) {outstanding--; free(p);} }
static void context_init(struct context *c) { memset(c,0,sizeof(*c)); }
static void context_destroy(struct context *c) { if(c->owned) contexts--; memset(c,0,sizeof(*c)); }
static void *symtab_search(struct symtab *t, const char *key) {
    static struct user_datum u={1}; static struct role_datum r={2};
    static struct type_datum good={3,false}, attr={4,true};
    if(t->live) live_work++;
    if(t->kind==0) return !strcmp(key,"u") ? &u : NULL;
    if(t->kind==1) return !strcmp(key,"r") ? &r : NULL;
    if(t->live && missing_live) return NULL;
    if(!strcmp(key,"good")) return &good;
    if(!strcmp(key,"attr")) return &attr;
    return NULL;
}
static int mls_context_to_sid(struct policydb *db, char oldc, char *p,
        struct context *c, struct sidtab *st, u32 def) {
    (void)st; (void)def;
    if(db->live) live_work++;
    if(oldc!=':' || strcmp(p,"s0")) return -EINVAL;
    c->owned=true; contexts++; return mls_error[db->live];
}
static bool policydb_context_isvalid(struct policydb *db, struct context *c) {
    if(db->live) live_work++;
    return !invalid_policy && c->user==1 && c->role==2 && c->type==3;
}
static int sidtab_context_to_sid(struct sidtab *st, struct context *c, u32 *sid) {
    assert(c->owned); insertions[st->live]++;
    if(st->live) live_work++;
    *sid=st->live ? 456 : 123;
    return sid_error[st->live];
}
"""
transition = r"""
struct ksu_task_security_struct { u32 sid; };
struct cred { struct ksu_task_security_struct sec; };
static struct cred cred;
static struct selinux_policy *backup_sepolicy=&backup;
static int committed, aborted;
static u32 current_sid(void) { return 11; }
static int ksu_avc_has_perm_compat(u32 a,u32 b,int c,int p,void *v) {
    (void)a;(void)c;(void)v;
    if(p==PROCESS__DYNTRANSITION) assert(b==456);
    return 0;
}
static struct cred *prepare_creds(void) { return &cred; }
static struct ksu_task_security_struct *selinux_cred(struct cred *c) {return &c->sec;}
static bool current_is_single_threaded(void) {return true;}
static int ksu_security_bounded_transition_compat(u32 a,u32 b) {(void)a;(void)b;return 0;}
static u32 ptrace_parent_sid(void) {return 0;}
static void commit_creds(struct cred *c) {assert(c==&cred);committed++;}
static void abort_creds(struct cred *c) {assert(c==&cred);aborted++;}
"""
main = r"""
static void reset(void) {
    assert(outstanding==0 && contexts==0 && rcu_depth==0);
    copies=live_work=insertions[0]=insertions[1]=0;
    missing_live=invalid_policy=fail_copy=sid_error[0]=sid_error[1]=mls_error[0]=mls_error[1]=0;
}
static int query(const char *s, u32 *sid, u32 *orig, int *orig_rc) {
    return security_context_to_sid_with_policy(&backup,s,strlen(s),sid,0,0,orig,orig_rc);
}
int main(void) {
    const char *invalid[]={"bad:r:good:s0","u:bad:good:s0","u:r:bad:s0",
        "u:r:attr:s0","u:r:good:bad_mls","missing_delimiters"};
    u32 sid=0, orig=0; int orig_rc=0;
    for(size_t i=0; i<sizeof(invalid)/sizeof(invalid[0]); i++) {
        reset(); assert(query(invalid[i],&sid,&orig,&orig_rc)==-EINVAL);
        assert(copies==1 && live_work==0 && insertions[0]==0 && insertions[1]==0);
    }
    reset(); invalid_policy=1;
    assert(query("u:r:good:s0",&sid,&orig,&orig_rc)==-EINVAL);
    assert(copies==1 && live_work==0);
    reset(); missing_live=1;
    assert(query("u:r:good:s0",&sid,&orig,&orig_rc)==0);
    assert(sid==123 && orig==0 && orig_rc==-EINVAL && insertions[0]==1 && insertions[1]==0);
    reset();
    assert(query("u:r:good:s0",&sid,&orig,&orig_rc)==0);
    assert(sid==123 && orig==456 && orig_rc==0 && copies==2);
    assert(insertions[0]==1 && insertions[1]==1);
    reset(); /* Queries without orig outputs retain global SID synchronization. */
    assert(query("u:r:good:s0",&sid,NULL,NULL)==0 && insertions[1]==1);
    reset(); sid_error[0]=-ENOMEM; sid_error[1]=-ESTALE;
    assert(query("u:r:good:s0",&sid,&orig,&orig_rc)==-ENOMEM && orig_rc==-ESTALE);
    assert(insertions[0]==1 && insertions[1]==1);
    reset(); mls_error[0]=-ENOMEM;
    assert(query("u:r:good:s0",&sid,&orig,&orig_rc)==-ENOMEM && live_work==0);
    reset(); mls_error[1]=-ENOMEM;
    /* The original dual parser takes live policy validity over live MLS rc. */
    assert(query("u:r:good:s0",&sid,&orig,&orig_rc)==0 && orig_rc==0);
    reset(); fail_copy=2;
    assert(query("u:r:good:s0",&sid,&orig,&orig_rc)==-ENOMEM && live_work==0);
    reset(); fail_copy=1;
    assert(query("u:r:good:s0",&sid,&orig,&orig_rc)==-ENOMEM);
    reset();
    reset();
    char valid[]="u:r:good:s0";
    assert(my_setprocattr("current",valid,strlen(valid))==(int)strlen(valid));
    assert(committed==1 && aborted==0 && cred.sec.sid==456);
    reset(); missing_live=1;
    assert(my_setprocattr("current",valid,strlen(valid))==-EINVAL && committed==1);
    reset();
    puts("PASS: actual parser, invalid-input lazy work, MLS cleanup, live SID sync, errno and allocation failure");
    return 0;
}
"""
with tempfile.TemporaryDirectory(prefix="ksu-parser-") as tmp:
    source=Path(tmp)/"parser.c"
    binary=Path(tmp)/"parser"
    source.write_text(harness+parser+"\n"+helper+transition+proc+main)
    subprocess.run([os.environ.get("CC","cc"),"-std=gnu11","-Wall","-Wextra",
                    "-Wno-unused-parameter","-Werror",str(source),"-o",str(binary)],
                   check=True,timeout=30)
    subprocess.run([str(binary)],check=True,timeout=15)
