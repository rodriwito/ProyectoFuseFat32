montaje= punto_montaje
fichero= file.img 

fuse_flags= -D_FILE_OFFSET_BITS=64 -lfuse -pthread

fat32 : fat32.o 
	gcc -g -o $@  $^ ${fuse_flags}
	mkdir -p $(montaje)
	
fat32.o : fat32.c fat32.h
	gcc -g -c -o $@  $< ${fuse_flags}


mount: fat32
	./fat32 $(fichero) $(montaje)

debug: fat32
	./fat32 -d $(fichero) $(montaje)

umount:
	fusermount -u $(montaje)
