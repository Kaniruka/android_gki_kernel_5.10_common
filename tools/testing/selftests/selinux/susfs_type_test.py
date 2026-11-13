#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual SUSFS add/lookup functions against colliding hash buckets.
This verifies full-key matching; it does not model kernel RCU concurrency.
"""
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[4]
source = (ROOT / "fs/susfs.c").read_text()
start = source.index("struct st_susfs_sus_type_hlist {")
end = source.index("\nstatic DEFINE_MUTEX(susfs_mutex_lock_sus_avd_allowed_hlist)", start)
real = source[start:end]
HARNESS = r"""
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
typedef uint32_t u32;
struct hlist_node {struct hlist_node *next;};
static struct hlist_node *SUS_TYPE_HLIST[1024];
static int susfs_mutex_lock_sus_type;
#define GFP_KERNEL 0
#define SUSFS_LOGE(...) ((void)0)
#define SUSFS_LOGI_RL(...) ((void)0)
#define mutex_lock(x) ((void)(x))
#define mutex_unlock(x) ((void)(x))
#define kzalloc(n,flags) calloc(1,n)
static unsigned bucket(u32 key) {return (u32)(key*0x61c88647U)>>22;}
#define entry(ptr,type,member) ((type *)((char *)(ptr)-offsetof(type,member)))
#define hash_for_each_possible_safe(table,obj,tmp,member,key) \
 for(struct hlist_node *p=(table)[bucket(key)];p && ((obj)=entry(p,__typeof__(*(obj)),member),(tmp)=p->next,1);p=(tmp))
#define hash_for_each_possible_rcu(table,obj,member,key) \
 for(struct hlist_node *p=(table)[bucket(key)];p && ((obj)=entry(p,__typeof__(*(obj)),member),1);p=p->next)
#define hash_add_rcu(table,node,key) do {(node)->next=(table)[bucket(key)];(table)[bucket(key)]=(node);}while(0)
"""
MAIN = r"""
int main(void){
 unsigned a=1,b=2,c;
 while(bucket(a)!=bucket(b))b++;
 c=b+1; while(bucket(a)!=bucket(c))c++;
 assert(!susfs_is_sus_type_rcu(a));
 assert(!susfs_is_sus_type_rcu(b));
 assert(susfs_add_sus_type("first",a)==0);
 assert(susfs_is_sus_type_rcu(a));
 assert(!susfs_is_sus_type_rcu(b));
 assert(susfs_add_sus_type("first duplicate",a)==-EINVAL);
 assert(susfs_add_sus_type("second distinct collision",b)==0);
 assert(susfs_is_sus_type_rcu(a));
 assert(susfs_is_sus_type_rcu(b));
 assert(!susfs_is_sus_type_rcu(c));
 assert(susfs_add_sus_type("second duplicate",b)==-EINVAL);
 while(SUS_TYPE_HLIST[bucket(a)]) {
  struct hlist_node *next=SUS_TYPE_HLIST[bucket(a)]->next;
  free(entry(SUS_TYPE_HLIST[bucket(a)],struct st_susfs_sus_type_hlist,node));
  SUS_TYPE_HLIST[bucket(a)]=next;
 }
 puts("PASS: actual SUSFS type functions preserve full keys across collisions and duplicates");
 return 0;
}
"""
with tempfile.TemporaryDirectory(prefix="susfs-type-") as temp:
    c = Path(temp) / "type.c"
    binary = Path(temp) / "type"
    c.write_text(HARNESS + real + MAIN)
    subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-Wall", "-Wextra",
                    "-Wno-unused-parameter", "-Werror", str(c), "-o", str(binary)],
                   check=True, timeout=30)
    subprocess.run([str(binary)], check=True, timeout=15)
