obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o libs/scth.o utils/crypto.o probes/probes.o utils/syscall.o utils/utils.o

all: reference_monitor_module reference_monitor_user

reference_monitor_user:
	$(CC) -Wall -Wextra -o user/user user/user.c
reference_monitor_module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
	rm user/user
