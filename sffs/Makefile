obj-m += the_sffs.o
the_sffs-objs += sffs.o src/fs.o src/file.o src/dir.o

CFLAGS_MODULE := -g

all: clean build

build: build-module build-user

build-module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

build-user:
	mkdir -p bin
	$(CC) -Wall -Wextra -o bin/makefs src/makefs.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
	rm -rf bin
