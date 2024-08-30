# soa

## Building and Running

### Clone Repository with submodules

```bash
git clone git@github.com:lioia/soa --recurse-submodules
```

### Build and install

```bash
make
make mount PASSWORD="password"
```

The `PASSWORD` variable is optional; the default value is "refmon_default_password"

### Uninstall

```bash
make umount
```

## Project Description

[**Specs**](./docs/specs.md)

The project was tested on the following Kernel versions:

- 4.19.0 on Linux Mint Debian Edition 4
- 5.4.0 on Linux Mint 20.3
- 5.10.103 on Linux Mint Debian Edition 5
- 5.15.0 on Linux Mint 21.3
- 6.1.52 on Linux Mint Debian Edition 6

### Reference Monitor

The Reference Monitor module handles a `struct reference_monitor` that contains
the monitor state. The relevant state for the reference monitor is:

- `enum reference_monitor_state state`: possible state of the reference monitor;
  it can be one of 4 values:
  - `RM_OFF`: the reference monitor is inactive and cannot be reconfigured
  - `RM_ON`: the reference monitor is active but cannot be reconfigured
  - `RM_REC_OFF`: the reference monitor is inactive but can be reconfigured
  - `RM_REC_ON`: the reference monitor is active and can be reconfigured
- `unsigned char *password_hash`: stores the SHA256 hash of the reference
  monitor password; the monitor never stores the password in clear, it is always
  encrypted before
- `spinlock_t lock`: lock for write operations on the RCU list
- `struct list_head list`: head of the RCU list containing the paths to monitor

Each RCU list entry has a pointer to the next element and the inode number of
the protected path

When loading the module, the Linux-sys_call_table-discoverer hacks 4 entries of
the syscall table and install custom functions (the discussion of the new
system calls, is in the next section). The init function then hashes the
password provided when inserting the module (or the default password),
initializes the spin lock, the RCU list and the probes (which will be discussed
in a later section). The probes are disabled by default because the initial
state of the monitor is OFF.

The cleanup function of the module frees the memory used by the reference
monitor (password hash, probes and the contents of the RCU list) and restore the
original state of the syscall table.

#### Syscalls

The 4 syscalls installed are the following:

- `change_password`: lets the user change the password of the reference monitor.
  This function checks if the euid is root and if the provided password is
  correct. If this checks pass, it hashes the new password provided and sets it
  as the new password of the reference monitor
- `set_state`: lets the user change the state of the reference monitor. It
  checks if the user is with euid root and if the password is correct. Then it
  updates the internal state of the monitor, enabling or disabling the probes
  according to the ON/OFF state
- `add_path`: lets the user add a new path to the protected paths. After
  checking the euid, the password and if the monitor is reconfigurable, it
  gets the `dentry` from the path (using the `kern_path` function) and searches
  the inode number of the dentry in the RCU list. If it finds a match, it early
  returns with an error, otherwise it creates a new entry and adds it to the
  RCU list
- `delete_path`: lets the user remove a protected paths. After the same checks
  of the `add_path` syscall, it gets the `dentry` of the path provided by the
  user, it searches the inode number in the RCU list and if it finds a match,
  it removes and frees the node from the list

#### Probes

The probes required to prevents write operation on the protected paths are
probing the following functions:

- `vfs_open`: prevents opening a file in write mode
- `security_inode_create`: prevents creation of new file in a protected
  directory
- `security_path_unlink`: prevents removal of protected files or files in a
  protected directory
- `security_inode_link`: prevent creation of links of protected files
- `security_path_mkdir`: prevent creation of new directories in already
  protected directories
- `security_path_rmdir`: prevent removal of a procted directory or if it's in a
  protected directory
- `security_path_rename`: prevent rename/move operations on protected
  files/directories
- `security_inode_symlink`: prevent creation of symlinks of protected
  files/directories

The probes (`kretprobe`) are configured with both a `entry_handler` and a
`handler`. The `entry_handler` is specific for each function and it checks if
the entities involved in the operation or its parent has a protected inode
number (searching it in the RCU list). If it finds a match, it fills the
`kretprobe_instance` data with the pathnames and type of operation and
returns 0, otherwise returns 1. If the `entry_handler` returns 0, the `handler`
function is automatically called. This function is responsible for creating the
tasks that will write to the log file, using the
`reference_monitor_packed_work` struct that contains the information required.
The work is then scheduled using the `__INIT_WORK` macro and the
`schedule_work` function.
The `handler` then sets the return value of the probed function to `-EACCES`, to
prevent the actual execution of the functionality.

#### Tasks

The task is responsible to compute the SHA256 hash of the offending program file
and write it into a log file (which will be described in the next section), or
in the `dmesg` log.

The task uses the `container_of` macro to get the
`reference_monitor_packed_work` struct from the `data` passed when scheduling.
If the SHA256 computation fails, it still tries to write the log line

### SingleFile FileSystem

This file system is implemented in another module, independent of the reference
monitor module. Starting with the example provided, the function `write_iter`
was implemented to enable the writing to the file.

When writing, a `mutex` is locked to handle concurrent writers.

### User Space Programs

#### User TUI

A terminal application has been developed to interact with the reference
monitor. The application requires to be ran with root euid. The application
lets the user call the syscall implemented

#### Tests

An additional user-space program was programmed to easily checks if the
functionalities of the reference monitor are implemented correctly.

This application creates a test environment, protects a file and a directory and
tries to execute the probed system calls (`create`, `open`, `unlink`, `link`,
`mkdir`, `rmdir`, `rename` and `symlink`)

## Editor Setup

To generate `compile_commands.json`, [bear](https://github.com/rizsotto/Bear)
is required:

```bash
bear -- make
```
