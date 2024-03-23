obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
