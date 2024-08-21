SYS_CALL_TABLE_ADDRESS = $(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)

# Build
all: build_modules build_user

build_modules:
	@echo "Building System Call Table Discoverer"
	@cd libs/sys_call_table_discoverer && $(MAKE) all
	@echo "Building Reference Monitor"
	@cd reference_monitor && $(MAKE) all
	@echo "Building SFFS"
	@cd sffs && $(MAKE) all

build_user:
	@echo "Building user-space application"
	@cd reference_monitor && $(MAKE) reference_monitor_user

clean:
	@cd libs/sys_call_table_discoverer && $(MAKE) clean
	@cd reference_monitor && $(MAKE) clean
	@cd sffs && $(MAKE) clean

# Mount modules
mount: mount_modules

mount_modules:
	@echo "Mounting System Call Table Discoverer"
	insmod libs/sys_call_table_discoverer/the_usctm.ko
	@echo "Mounting Reference Monitor"
	insmod reference_monitor/the_reference_monitor.ko the_syscall_table=$(SYS_CALL_TABLE_ADDRESS)
	@echo "Mounting File System"
	insmod sffs/the_sffs.ko

mount_fs:
	mkdir -p /tmp/sffs/mount
	mount -o loop -t sffs ./sffs/bin/image /tmp/sffs/mount

make_fs:
	dd bs=4096 count=100 if=/dev/zero of=./sffs/bin/image
	./sffs/bin/makefs ./sffs/bin/image

umount: umount_fs umount_modules

umount_modules:
	@echo "Removing System Call Table Discoverer"
	rmmod the_usctm
	@echo "Removing Reference Monitor"
	rmmod the_reference_monitor
	@echo "Removing SFFS"
	rmmod the_sffs 

umount_fs:
	@echo "Removing File System"
	sudo umount -R /tmp/sffs/mount
