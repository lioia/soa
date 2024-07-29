obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o libs/scth.o \
	probes/probes.o utils/syscall.o utils/utils.o tasks/tasks.o \
	fs/fs.o fs/file.o fs/dir.o

all: reference_monitor_module reference_monitor_user reference_monitor_fs

reference_monitor_module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

reference_monitor_user:
	mkdir -p bin
	$(CC) -Wall -Wextra -o bin/user user/user.c user/io.c

reference_monitor_fs:
	mkdir -p bin
	$(CC) -Wall -Wextra -o bin/makefs fs/makefs.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
	rm -rf bin
