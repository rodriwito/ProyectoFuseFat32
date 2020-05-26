**Punto de partida para desarrollo de driver FUSE Fat32**

Actualmente es capaz de montar y listar contenidos de una imagen Fat32.

No puede abrir ficheros (en el estado actual).

## USO

* Para compilar: `make`
* Para depurar:  `make debug`
* Para montar y desmontar: `make mount` `make umount` 
* Las reglas de Makefile usan el fichero file.img, así que debe estar descomprimido (`unzip file.img.zip`)

Hay mensajes por stderr que son visibles al depurar, en particular al iniciar el FS se muestran parámentros interesantes extraídos de
los sectores inciciales: 
```
FATs #:       0x00002 = 2
1st FAT off:  0x04000 = 16384
FAT size(sec):0x00301 = 769
Clusters #:   0x18080 = 98432
Clusters off: 0xc4400 = 803840
Cluster size: 0x00200 = 512
Sector size : 0x00200 = 512
Root Cluster: 0x00002 = 2
num_entries:  0x00010 = 16
- Info in FS info sector:
  free_clusters:     0x1807a = 98426
  last_used_cluster: 0x00005 = 5
FS total : 50.40MB
FS free  : 50.39MB
```
## Operaciones con ficheros
Se han implementado las operaciones fuse:

* init   (incicialización del FS)
* getattr
* readdir

## Funciones auxiliares
Se han implementado las funciones:

* readFAT() para leer una entrada de la primera copia de la FAT (no está probado)
* readCLUSTER() para leer un cluster del área de datos
* entrada_vacia() para comprobar si una entrada de directorio está vacía 
* get_long_filename() obtiene el nombre completo de un fichero/directorio a partir de su entrada
* encuentra_entrada() encuentra la entrada de directorio en la imagen Fat32 de un path fuse
* conv_time() conversión de fechas FAT32->unix

## Estructuras de datos en fat32.h

* bios_param_block  estructura inicio de FAT32 (sector 0) con datos sobre la geometría de la partición
* fs_information_sector  sector 1 con información del estado de los clusters usados/libres
* directory_entry  entrada de directorio FAT32 estándar
* long_filename_entry entrada de directorio FAT32 para extender nombre de fichero
* structura_mis_datos estructura para manejar el FS en fuse
* además de las estrutcturas se han definido símbolos para los attributos en la entrada de directorio:
``` C
// directory entry attributes:
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN 0x02
#define ATTR_SYSTEM 0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20
#define ATTR_LONG_NAME 0x0F
#define ATTR_DELETED 0xE5   // al principio del nombre
```

## Imagen ejemplo
Descomprimir el fichero zip y usarlo como ejemplo de imagen Fat32. En el Makefile se usa este fichero `file.img` en las reglas de montar y depurar 

Contiene un par de ficheros de texto uno de ellos en un subdirectorio.

Se puede explorar la imagen de ejemplo con: `hexdump -C file.img | more`

Hay un volcado comentado en el fichero `file.img.dump`

Se podría montar la imagen en un directorio para modificarla y hacer pruebas o lo que necesitéis:

`sudo losetup /dev/loop1 file.img`

`sudo mount /dev/loop1 /mnt`


sudo losetup /dev/loop20 file.img
sudo mount /dev/loop20 /mnt


Para desmontar:

`sudo umount /mnt`

`sudo losetup -d /dev/loop1`


Para modificarlo desde la carpeta:
chown -R rodriwito:rodriwito /mnt

toda la ejecucion:

cd Desktop/master/
sudo losetup /dev/loop20 file.img
sudo mount /dev/loop20 /mnt
cd
sudo su
chown -R rodriwito:rodriwito /mnt


