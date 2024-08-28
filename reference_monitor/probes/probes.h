#ifndef PROBES_H
#define PROBES_H

#include <linux/dcache.h>

// Data passed from entry handler to post handler; used to create the deferred work
struct reference_monitor_probe_data {
  char *primary_file_path;        // Path of the first path
  size_t primary_file_path_len;   // Length of the first path
  char *secondary_file_path;      // Path of the second path (e.g. output of a mv command)
  size_t secondary_file_path_len; // Length of the second path
  char *operation;                // Operation that triggered the probe
};

/**
 * @brief Creates and registers the probe
 *
 * @return 0 on success; any other number otherwise
 */
int probes_init(void);

/**
 * @brief Unregister the probes
 */
void probes_deinit(void);

/**
 * @brief Enables the probes
 *
 * @return 0 on success; any other number otherwise
 */
int probes_enable(void);

/**
 * @brief Disables the probes
 *
 * @return 0 on success; any other number otherwise
 */
int probes_disable(void);

/**
 * @brief Helper function to add data into the struct passed from the entry handler to the post handelr
 *
 * @param data reference to the struct
 * @param operation what triggered the probe
 * @param primary dentry of the first file
 * @param secondary dentry of the second file
 * @return 0 on success; 1 otherwise
 */
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

// Macro for enabling a probe from the function name
#define ENABLE_PROBE(func_name)                                                                                        \
  if ((ret = enable_kretprobe(&func_name##_probe)) < 0) {                                                              \
    pr_err("%s: enable_kretprobe failed for %s: %d\n", MODNAME, #func_name, ret);                                      \
    return ret;                                                                                                        \
  }

// Macro for disabling a probe from the function name
#define DISABLE_PROBE(func_name)                                                                                       \
  if ((ret = disable_kretprobe(&func_name##_probe)) < 0) {                                                             \
    pr_err("%s: disable_kretprobe failed for %s: %d\n", MODNAME, #func_name, ret);                                     \
    return ret;                                                                                                        \
  }

#endif // !PROBES_H
