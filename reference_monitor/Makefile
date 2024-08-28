obj-m += the_reference_monitor.o
the_reference_monitor-objs += reference_monitor.o libs/scth.o probes/probes.o \
	utils/syscall.o utils/paths.o utils/crypto.o utils/credentials.o tasks/tasks.o

CFLAGS_MODULE := -g

all: clean build

build: build-module build-user

build-module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

build-user:
	mkdir -p bin
	$(CC) -Wall -Wextra -o bin/user user/user.c user/io.c user/syscalls.c user/utils.c
	$(CC) -Wall -Wextra -o bin/tests user/tests.c user/utils.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
	rm -rf bin
