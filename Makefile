SYS_CALL_TABLE_ADDRESS = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)

# Build
all: modules user

modules:
	@echo "Building System Call Table Discoverer"
	@cd libs/sys_call_table_discoverer && $(MAKE) all
	@echo "Building Reference Monitor"
	@cd reference_monitor && $(MAKE) all

user:
	@echo "Building user-space application"
	@cd reference_monitor && $(MAKE) reference_monitor_user

clean:
	@cd libs/sys_call_table_discoverer && $(MAKE) clean
	@cd reference_monitor && $(MAKE) clean

# Mount module and fs 
mount: mount_syscall mount_refmon

mount_syscall:
	@echo "Mounting System Call Table Discoverer"
	insmod libs/sys_call_table_discoverer/the_usctm.ko

mount_refmon:
	@echo "Mounting Reference Monitor"
	insmod reference_monitor/the_reference_monitor.ko the_syscall_table=$(SYS_CALL_TABLE_ADDRESS)

mount_fs:
	@echo "Mounting File System"
	mkdir -p /tmp/reference_monitor/mount
	dd bs=4096 count=100 if=/dev/zero of=./reference_monitor/bin/image
	./reference_monitor/bin/makefs ./reference_monitor/bin/image
	mount -o loop -t singlefilefs ./reference_monitor/bin/image /tmp/reference_monitor/mount

umount: umount_fs umount_modules

umount_modules:
	@echo "Removing System Call Table Discoverer"
	rmmod the_usctm
	@echo "Removing Reference Monitor"
	rmmod the_reference_monitor

umount_fs:
	@echo "Removing File System"
	sudo umount -R /tmp/reference_monitor/mount
