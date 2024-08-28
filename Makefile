SYS_CALL_TABLE_ADDRESS = $(shell sudo cat /sys/module/the_usctm/parameters/sys_call_table_address)

all: clean build
build: build-modules build-user
install: clean build mount
mount: mount-modules mkfs mount-fs
mount-modules: --mount-usctm --mount-rm --mount-sffs
umount: umount-modules umount-fs

clean:
	@cd libs/sys_call_table_discoverer && $(MAKE) clean
	@cd reference_monitor && $(MAKE) clean
	@cd sffs && $(MAKE) clean

build-modules:
	@echo "Building System Call Table Discoverer"
	@cd libs/sys_call_table_discoverer && $(MAKE) all
	@echo "Building Reference Monitor Module"
	@cd reference_monitor && $(MAKE) build-module
	@echo "Building SFFS Module"
	@cd sffs && $(MAKE) build-module

build-user:
	@echo "Building Reference Monitor User"
	@cd reference_monitor && $(MAKE) build-user
	@echo "Building SFFS User"
	@cd sffs && $(MAKE) build-user

--mount-usctm:
	@echo "Mounting System Call Table Discoverer Module"
	sudo insmod libs/sys_call_table_discoverer/the_usctm.ko

--mount-rm:
	@echo "Mounting Reference Monitor Module"
	sudo insmod reference_monitor/the_reference_monitor.ko the_syscall_table=$(SYS_CALL_TABLE_ADDRESS)

--mount-sffs:
	@echo "Mounting Single File File System Module"
	sudo insmod sffs/the_sffs.ko

mount-fs:
	@echo "Mounting Single File File System Image"
	mkdir -p /tmp/sffs/mount
	sudo mount -o loop -t sffs ./sffs/bin/image /tmp/sffs/mount

mkfs:
	dd bs=4096 count=100 if=/dev/zero of=./sffs/bin/image
	./sffs/bin/makefs ./sffs/bin/image

umount-modules:
	@echo "Removing System Call Table Discoverer"
	sudo rmmod the_usctm
	@echo "Removing Reference Monitor"
	sudo rmmod the_reference_monitor

umount-fs:
	@echo "Removing File System"
	sudo umount -R /tmp/sffs/mount
	@echo "Removing Single File File System"
	sudo rmmod the_sffs 
