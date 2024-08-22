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

#endif // !PROBES_H
