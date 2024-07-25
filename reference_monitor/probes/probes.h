#ifndef PROBES_H
#define PROBES_H

void probes_init(void);
int probes_register(void);
void probes_unregister(void);

// Macro for creating a probe from the function name
// do {} while(0) is needed to ensure that it runs as a single statement
#define CREATE_PROBE(func_name)                                                                                        \
  do {                                                                                                                 \
    func_name##_probe.kp.symbol_name = #func_name;                                                                     \
    func_name##_probe.entry_handler = (kretprobe_handler_t)func_name##_probe_entry_handler;                            \
    func_name##_probe.handler = (kretprobe_handler_t)probe_post_handler;                                               \
    func_name##_probe.maxactive = -1;                                                                                  \
  } while (0)

// Macro for registering a probe from the function name
#define REGISTER_PROBE(func_name)                                                                                      \
  if ((ret = register_kretprobe(&func_name##_probe)) < 0) {                                                            \
    pr_err("%s: register_kretprobe failed for %s: %d\n", MODNAME, #func_name, ret);                                    \
    return ret;                                                                                                        \
  }

#define HANDLE_PROBE(dentry_expr, func)                                                                                \
  do {                                                                                                                 \
    int ret = 1;                                                                                                       \
    char *path = NULL;                                                                                                 \
    struct dentry *dentry = NULL;                                                                                      \
    struct reference_monitor_path *entry = NULL;                                                                       \
                                                                                                                       \
    if (refmon.state == RM_OFF || refmon.state == RM_REC_OFF)                                                          \
      return ret;                                                                                                      \
                                                                                                                       \
    dentry = dentry_expr;                                                                                              \
                                                                                                                       \
    /* Get path from dentry */                                                                                         \
    path = get_complete_path_from_dentry(dentry);                                                                      \
    /* Search for the path in the rcu list */                                                                          \
    entry = search_for_path_in_list(path);                                                                             \
                                                                                                                       \
    /* No entry found; */                                                                                              \
    if (entry == NULL)                                                                                                 \
      goto exit;                                                                                                       \
                                                                                                                       \
    /* Entry found; post handler has to be activated */                                                                \
    ret = 0;                                                                                                           \
                                                                                                                       \
    /* TODO: deferred work (write to fs, calculate hash) */                                                            \
                                                                                                                       \
  exit:                                                                                                                \
    if (path)                                                                                                          \
      kfree(path);                                                                                                     \
    return ret;                                                                                                        \
  } while (0)
#endif // !PROBES_H
