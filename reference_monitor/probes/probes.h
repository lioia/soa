#ifndef PROBES_H
#define PROBES_H

#include <linux/dcache.h>

struct reference_monitor_probe_data {
  char *primary_file_path;
  char *secondary_file_path;
  char *operation;
};

int probes_init(void);
void probes_deinit(void);
int probes_enable(void);
int probes_disable(void);

int fill_probe_data(struct reference_monitor_probe_data *data, char *operation, struct dentry *primary,
                    struct dentry *secondary);

// Macro for creating a probe from the function name
// do {} while(0) is needed to ensure that it runs as a single statement
#define CREATE_PROBE(func_name)                                                                                        \
  do {                                                                                                                 \
    func_name##_probe.kp.symbol_name = #func_name;                                                                     \
    func_name##_probe.entry_handler = (kretprobe_handler_t)func_name##_probe_entry_handler;                            \
    func_name##_probe.handler = (kretprobe_handler_t)probe_post_handler;                                               \
    func_name##_probe.maxactive = -1;                                                                                  \
    func_name##_probe.data_size = sizeof(struct reference_monitor_probe_data);                                         \
  } while (0)

// Macro for registering a probe from the function name
#define REGISTER_PROBE(func_name)                                                                                      \
  if ((ret = register_kretprobe(&func_name##_probe)) < 0) {                                                            \
    pr_err("%s: register_kretprobe failed for %s: %d\n", MODNAME, #func_name, ret);                                    \
    return ret;                                                                                                        \
  }

#define ENABLE_PROBE(func_name)                                                                                        \
  if ((ret = enable_kretprobe(&func_name##_probe)) < 0) {                                                              \
    pr_err("%s: enable_kretprobe failed for %s: %d\n", MODNAME, #func_name, ret);                                      \
    return ret;                                                                                                        \
  }

#define DISABLE_PROBE(func_name)                                                                                       \
  if ((ret = disable_kretprobe(&func_name##_probe)) < 0) {                                                             \
    pr_err("%s: disable_kretprobe failed for %s: %d\n", MODNAME, #func_name, ret);                                     \
    return ret;                                                                                                        \
  }

#endif // !PROBES_H
