obj-m += the_sffs.o
the_sffs-objs += sffs.o src/fs.o src/file.o src/dir.o

CFLAGS_MODULE := -g

all: clean build mount

build:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	mkdir -p bin
	$(CC) -Wall -Wextra -o bin/makefs src/makefs.c

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean 
	rm -rf bin
