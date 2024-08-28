#ifndef USER_H
#define USER_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
#define CHANGE_PASSWORD 174
#define SET_STATE 177
#define ADD_PATH 178
#define DELETE_PATH 180
#else
#define CHANGE_PASSWORD 156
#define SET_STATE 174
#define ADD_PATH 177
#define DELETE_PATH 178
#endif

#endif // !USER_H
