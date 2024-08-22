SYS_CALL_TABLE_ADDRESS = $(shell sudo cat /sys/module/the_usctm/parameters/sys_call_table_address)

all: clean build mount

build:
	@echo "Building System Call Table Discoverer"
	@cd libs/sys_call_table_discoverer && $(MAKE) all
	@echo "Building Reference Monitor"
	@cd reference_monitor && $(MAKE) build
	@echo "Building SFFS"
	@cd sffs && $(MAKE) build

clean:
	@cd libs/sys_call_table_discoverer && $(MAKE) clean
	@cd reference_monitor && $(MAKE) clean
	@cd sffs && $(MAKE) clean

# Mount modules
mount: _mount-usctm _mount-rm mount-sffs

_mount-usctm:
	@echo "Mounting System Call Table Discoverer"
	sudo insmod libs/sys_call_table_discoverer/the_usctm.ko

_mount-rm:
	@echo "Mounting Reference Monitor"
	sudo insmod reference_monitor/the_reference_monitor.ko the_syscall_table=$(SYS_CALL_TABLE_ADDRESS)

mount-sffs:
	@echo "Mounting Single File File System"
	sudo insmod sffs/the_sffs.ko

mount-fs:
	mkdir -p /tmp/sffs/mount
	sudo mount -o loop -t sffs ./sffs/bin/image /tmp/sffs/mount

make-fs:
	dd bs=4096 count=100 if=/dev/zero of=./sffs/bin/image
	./sffs/bin/makefs ./sffs/bin/image

umount:
	@echo "Removing System Call Table Discoverer"
	sudo rmmod the_usctm
	@echo "Removing Reference Monitor"
	sudo rmmod the_reference_monitor

umount-fs:
	@echo "Removing File System"
	sudo umount -R /tmp/sffs/mount
	@echo "Removing Single File File System"
	sudo rmmod the_sffs 
