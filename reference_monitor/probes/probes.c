#include <asm/ptrace.h>
#include <linux/kprobes.h>
#include <linux/printk.h>

#include "../reference_monitor.h"
#include "probes.h"

// File create/edit
static struct kretprobe do_filp_open_probe;

// File delete
static struct kretprobe do_unlinkat_probe;

// File link
static struct kretprobe do_linkat_probe;

// Directory create
static struct kretprobe do_mkdirat_probe;

// Directory delete
static struct kretprobe do_rmdir_probe;

// Directory edit (file move)
static struct kretprobe do_renameat2_probe;

// Symbolic Link
static struct kretprobe do_symlinkat_probe;

static int do_filp_open_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }
static int do_filp_open_probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

static int do_unlinkat_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }
static int do_unlinkat_probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

static int do_linkat_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }
static int do_linkat_probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

static int do_mkdirat_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }
static int do_mkdirat_probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

static int do_rmdir_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }
static int do_rmdir_probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

static int do_renameat2_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }
static int do_renameat2_probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

static int do_symlinkat_probe_entry_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }
static int do_symlinkat_probe_post_handler(struct kretprobe_instance *p, struct pt_regs *regs) { return 0; }

void probes_init(void) {
  do_filp_open_probe.kp.symbol_name = "do_filp_open";
  do_filp_open_probe.entry_handler = (kretprobe_handler_t)do_filp_open_probe_entry_handler;
  do_filp_open_probe.handler = (kretprobe_handler_t)do_filp_open_probe_post_handler;
  do_filp_open_probe.maxactive = -1;

  do_unlinkat_probe.kp.symbol_name = "do_unlinkat";
  do_unlinkat_probe.entry_handler = (kretprobe_handler_t)do_unlinkat_probe_entry_handler;
  do_unlinkat_probe.handler = (kretprobe_handler_t)do_unlinkat_probe_post_handler;
  do_unlinkat_probe.maxactive = -1;

  do_linkat_probe.kp.symbol_name = "do_linkat";
  do_linkat_probe.entry_handler = (kretprobe_handler_t)do_linkat_probe_entry_handler;
  do_linkat_probe.handler = (kretprobe_handler_t)do_linkat_probe_post_handler;
  do_linkat_probe.maxactive = -1;

  do_mkdirat_probe.kp.symbol_name = "do_mkdirat";
  do_mkdirat_probe.entry_handler = (kretprobe_handler_t)do_mkdirat_probe_entry_handler;
  do_mkdirat_probe.handler = (kretprobe_handler_t)do_mkdirat_probe_post_handler;
  do_mkdirat_probe.maxactive = -1;

  do_rmdir_probe.kp.symbol_name = "do_rmdir";
  do_rmdir_probe.entry_handler = (kretprobe_handler_t)do_rmdir_probe_entry_handler;
  do_rmdir_probe.handler = (kretprobe_handler_t)do_rmdir_probe_post_handler;
  do_rmdir_probe.maxactive = -1;

  do_renameat2_probe.kp.symbol_name = "do_renameat2";
  do_renameat2_probe.entry_handler = (kretprobe_handler_t)do_renameat2_probe_entry_handler;
  do_renameat2_probe.handler = (kretprobe_handler_t)do_renameat2_probe_post_handler;
  do_renameat2_probe.maxactive = -1;

  do_symlinkat_probe.kp.symbol_name = "do_symlinkat";
  do_symlinkat_probe.entry_handler = (kretprobe_handler_t)do_symlinkat_probe_entry_handler;
  do_symlinkat_probe.handler = (kretprobe_handler_t)do_symlinkat_probe_post_handler;
  do_symlinkat_probe.maxactive = -1;
}

int probes_register(void) {
  int ret;

  if ((ret = register_kretprobe(&do_filp_open_probe)) < 0) {
    printk("%s: probes registration failed at do_filp_open: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&do_unlinkat_probe)) < 0) {
    printk("%s: probes registration failed at do_unlinkat: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&do_linkat_probe)) < 0) {
    printk("%s: probes registration failed at do_linkat: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&do_mkdirat_probe)) < 0) {
    printk("%s: probes registration failed at do_mkdirat: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&do_rmdir_probe)) < 0) {
    printk("%s: probes registration failed at do_rmdir: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&do_renameat2_probe)) < 0) {
    printk("%s: probes registration failed at do_renameat2: %d\n", MODNAME, ret);
    return ret;
  }
  if ((ret = register_kretprobe(&do_symlinkat_probe)) < 0) {
    printk("%s: probes registration failed at do_symlinkat: %d\n", MODNAME, ret);
    return ret;
  }
  return 0;
}

void probes_unregister(void) {
  unregister_kretprobe(&do_filp_open_probe);
  unregister_kretprobe(&do_unlinkat_probe);
  unregister_kretprobe(&do_linkat_probe);
  unregister_kretprobe(&do_mkdirat_probe);
  unregister_kretprobe(&do_rmdir_probe);
  unregister_kretprobe(&do_renameat2_probe);
  unregister_kretprobe(&do_symlinkat_probe);
}
