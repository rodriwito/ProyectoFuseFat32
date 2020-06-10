#define FUSE_USE_VERSION 26
#include <stdlib.h>
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "fat32.h"

// lee posición i de la FAT
int32_t readFAT(int32_t i, struct structura_mis_datos *mis_datos)
{
    int32_t data;
    // habría que cargar la FAT completa a memoria y dejar de leer del disco? sería peligroso? podría ponerse como opción
    pread(mis_datos->fh, (void*) &data, 4, mis_datos->fat_offset + (i * 4));
    return data;
}

void writeFAT(int32_t lugar, int32_t data,struct structura_mis_datos *mis_datos){
	fprintf(stderr,"Ponemos el cluster %i con el valor %i\n",lugar,data);
	pwrite(mis_datos->fh, (void*) &data, 4, mis_datos->fat_offset + (lugar * 4));
	//Escribimos en la segunda FAT;
	pwrite(mis_datos->fh, (void*) &data, 4, mis_datos->fat_offset + (lugar * 4) + (mis_datos->bpb->sectors_per_fat * mis_datos->bpb->bytes_sector));
}

// lee cluster i en buffer
void readCLUSTER(int32_t i, char * buffer, struct structura_mis_datos *mis_datos)
{
    pread(mis_datos->fh, (void*) buffer, mis_datos->cluster_size, mis_datos->clusters_offset + (i- mis_datos->bpb->root_cluster_number)* mis_datos->cluster_size);
    // mis_datos->bpb->root_cluster_number es normalmente 2, es el cluster donde está el directorio raiz y es el primero útil
    // el primer cluster del área de datos es el 2, porque las entradas del cluster 0 y 1 están reservadas y no tienen espacio en disco.
}

// comprueba si está vacía la entrada de directorio
int entrada_vacia(struct directory_entry *dir_entry)
{
    return(dir_entry->Short_Filename[0] == '\0');
}

//Recordarque cuando creemos un directorio acordarnos de ponerlo como unica entrada de directorio
//obtiene el nombre completo de una entrada de directorio
char *get_long_filename(char *cluster_buffer, int entry)
{
    struct directory_entry * special_dir;
    struct long_filename_entry * lfn_entry;

    char *name = (char*)malloc(256);

    special_dir = (struct directory_entry *)(cluster_buffer + (sizeof(struct long_filename_entry)*(entry)));
    if(!strncmp("..", special_dir->Short_Filename, 2)) {
        strncpy(name, "..", 3);
    } else if(!strncmp(".", special_dir->Short_Filename, 1)) {
        strncpy(name, ".", 2);
    } else {
        int y=0;
        lfn_entry = (struct long_filename_entry *) (cluster_buffer + (sizeof(struct long_filename_entry)*(entry-1)));
        if(lfn_entry->attribute != ATTR_LONG_NAME)
        {  // no tiene nombre con entrada larga
			int z;
            for(z = 0; z < 8 && special_dir->Short_Filename[z]!=32; z++)  name[y++] = special_dir->Short_Filename[z];
            if(special_dir->Short_File_Extension[0]!=32)
            {
				name[y++] = '.';
				for(z = 0; z < 3 && special_dir->Short_Filename[z]!=32; z++)  name[y++] = special_dir->Short_File_Extension[z];
			}
		}	
		else
		{
        // recorre todos las entradas largas asociadas desde la última a la primera
        for(int x = 1; x < 20 && lfn_entry->attribute == ATTR_LONG_NAME; x++)
        {
            int z;
            for(z = 0; z < 5; z++)  name[y++] = lfn_entry->name_1[z*2];
            for(z = 0; z < 6; z++)  name[y++] = lfn_entry->name_2[z*2];
            for(z = 0; z < 2; z++)  name[y++] = lfn_entry->name_3[z*2];
            lfn_entry = (struct long_filename_entry *) (cluster_buffer + (sizeof(struct long_filename_entry)*(entry-x-1)));
        }
     }
		name[y]='\0'; // fin de cadena
    }
    return name; //remember to free name
}

// busca entrada por nombre desde el directorio raiz
//MODIFICA EL PATH, HABRIA QUE TRATAR ESO
struct directory_entry *encuentra_entrada(char *path, struct structura_mis_datos *mis_datos)
{
    int next = mis_datos->bpb->root_cluster_number;

    char *token = strtok(path, "/"); // busca primera parte del path
    int dir_entries_per_cluster = mis_datos->num_entries;

    struct directory_entry *dir_entry, *copy;

    if(!strcmp(path, "/")) // es el directorio raiz, no hay que continuar buscando
    {
        copy=(struct directory_entry*) malloc(sizeof(struct directory_entry));
        copy->First_Cluster_High = mis_datos->bpb->root_cluster_number & 0xFF00;
        copy->First_Cluster_Low =  mis_datos->bpb->root_cluster_number & 0x00FF;
        return copy;
    }

    // leo el cluster del directorio raiz
    char *cluster_buffer = (char*)malloc(mis_datos->cluster_size);
    readCLUSTER(next, cluster_buffer, mis_datos);

    while(token != NULL) {
		int x;
        for(x = 0; x < dir_entries_per_cluster; x++)
        {
            dir_entry = (struct directory_entry *)(cluster_buffer + (sizeof(struct long_filename_entry)*x));

            if(dir_entry->Short_Filename[0]=='\0') { //entrada vacía, fin de directorio. Sólo se llega aquí si el path no existe
                free(cluster_buffer);
                return NULL;
            }

            char *lfn = get_long_filename(cluster_buffer, x);

            fprintf(stderr,"token: %s , lfn: %s\n",token,lfn);

            if(!strcmp(token, lfn)) // lo encontramos
            {
                if(dir_entry->Attributes & ATTR_DIRECTORY)
                {
                    token = strtok(NULL, "/");
                    if(token == NULL) { // final del path
                        copy=(struct directory_entry*) malloc(sizeof(struct directory_entry));
                        memcpy(copy,dir_entry,sizeof(struct directory_entry));
                        fprintf(stderr,"Fat32 entry found for path (dir): %s\n",lfn);
                        free(cluster_buffer);
                        free(lfn);
                        return copy; // devuelvo copia de la entrada del directorio
                    }
                    next = ((dir_entry->First_Cluster_High<<16)|dir_entry->First_Cluster_Low);
                    readCLUSTER(next, cluster_buffer, mis_datos);
                    x = 0; // seguimos buscando desde el principio del siguiente directorio
                    break;
                } else {
                    token = strtok(NULL, "/");
                    if(token == NULL) { // final del path
                        copy=(struct directory_entry*) malloc(sizeof(struct directory_entry));
                        memcpy(copy,dir_entry,sizeof(struct directory_entry));
                        fprintf(stderr,"Fat32 entry found for path (file): %s\n",lfn);
                        free(cluster_buffer);
                        free(lfn);
                        return copy; // es un fichero, devuelvo su entrada
                    }
                    free(cluster_buffer);
                    free(lfn);
                    return NULL; // error no es el final del path, pero no es directorio ¿?
                }
            }
            free(lfn);
        }
        if(x != 0){
			next = readFAT(next,mis_datos);
			if((next&FIN) == FIN){
				 free(cluster_buffer);
				 return NULL;
			}
			readCLUSTER(next, cluster_buffer, mis_datos);
		}
    }
    free(cluster_buffer);
    return NULL; // terminamos de buscar y no encontramos el path
}

//MODIFICA EL PATH, HABRIA QUE TRATAR ESO
int encuentrapos(char *path, struct structura_mis_datos *mis_datos)
{
    int next = mis_datos->bpb->root_cluster_number;

    char *token = strtok(path, "/"); // busca primera parte del path
    int dir_entries_per_cluster = mis_datos->num_entries;

    struct directory_entry *dir_entry, *copy;
	if(!strcmp(path, "/")) // es el directorio raiz, no hay que continuar buscando
    {
        return 0;
    }
    // leo el cluster del directorio raiz
    char *cluster_buffer = (char*)malloc(mis_datos->cluster_size);
    readCLUSTER(next, cluster_buffer, mis_datos);

    while(token != NULL) {
		int x;
        for(x = 0; x < dir_entries_per_cluster; x++)
        {
            dir_entry = (struct directory_entry *)(cluster_buffer + (sizeof(struct long_filename_entry)*x));

            char *lfn = get_long_filename(cluster_buffer, x);

            fprintf(stderr,"token: %s , lfn: %s\n",token,lfn);

            if(!strcmp(token, lfn)) // lo encontramos
            {
                if(dir_entry->Attributes & ATTR_DIRECTORY)
                {
                    token = strtok(NULL, "/");
                    if(token == NULL) { // final del path
                        fprintf(stderr,"Fat32 entry found for path (dir): %s\n",lfn);
                        free(cluster_buffer);
                        free(lfn);
                        return (mis_datos->clusters_offset + (next- mis_datos->bpb->root_cluster_number)* mis_datos->cluster_size + 32*x);
                    }
                    next = ((dir_entry->First_Cluster_High<<16)|dir_entry->First_Cluster_Low);
                    readCLUSTER(next, cluster_buffer, mis_datos);
                    x = 0; // seguimos buscando desde el principio del siguiente directorio
                    break;
                } else {
                    token = strtok(NULL, "/");
                    if(token == NULL) { // final del path
                        fprintf(stderr,"Fat32 entry found for path (file): %s\n",lfn);
                        free(cluster_buffer);
                        free(lfn);                        
                        return (mis_datos->clusters_offset + (next- mis_datos->bpb->root_cluster_number)* mis_datos->cluster_size + 32*x);
                    }
                    free(cluster_buffer);
                    free(lfn);
                    return 0; // error no es el final del path, pero no es directorio ¿?
                }
            }
            free(lfn);
        }
        if(x != 0){
			next = readFAT(next,mis_datos);
			if((next & FIN) == FIN){
				 free(cluster_buffer);
				 return 0;
			}
			readCLUSTER(next, cluster_buffer, mis_datos);
		}
    }
    free(cluster_buffer);
    return 0; // terminamos de buscar y no encontramos el path
}


// convierte el formato de la fecha
time_t conv_time(uint16_t date_entry, uint16_t time_entry) {
    struct tm * time_info;
    time_t raw_time;

    time(&raw_time);
    time_info = localtime(&raw_time);
    time_info->tm_sec = (time_entry & 0x1f) << 1;
    time_info->tm_min = (time_entry & 0x1E0) >> 5;
    time_info->tm_hour = (time_entry & 0xFE00) >> 11;
    time_info->tm_mday = date_entry & 0x1F;
    time_info->tm_mon = ((date_entry & 0x1E0) >> 5) - 1;
    time_info->tm_year = ((date_entry & 0xFE00) >> 9) + 80;
    return mktime(time_info);
}


//Encuentra la primera posicion libre en la fat.
//Habria que acotarlo al numero de bloques en la FAT

//(mis_datos->bpb->sectors_per_fat * mis_datos->bpb->bytes_sector)/4
int encontrarPosLibre(struct structura_mis_datos *mis_datos){
	int i = 0;
	while(i != (mis_datos->bpb->sectors_per_fat * mis_datos->bpb->bytes_sector/4)){
		if(readFAT(i,mis_datos) == 0){
			return i;
		}
		i++;
	}
}

///***************************************************
/// inicializa el sistema de ficheros
static void *FAT32_init(struct fuse_conn_info *conn)
{
    struct structura_mis_datos *mis_datos= (struct structura_mis_datos *) fuse_get_context()->private_data;

    mis_datos->bpb = (struct bios_param_block*)malloc(sizeof(struct bios_param_block));
    pread(mis_datos->fh, (void*) mis_datos->bpb, sizeof(struct bios_param_block),0); // leo la estructura bios_param_block del principio de la imagen FAT32 sector 0

    mis_datos->fsis = (struct fs_information_sector*)malloc(sizeof(struct fs_information_sector));
    // leo la estructura fs_information_sector del principio de la imagen FAT32 sector 1
    pread(mis_datos->fh, (void*) mis_datos->fsis, sizeof(struct fs_information_sector),mis_datos->bpb->bytes_sector); 
    
    //calculo posiciones básicas
    mis_datos->fat_offset = mis_datos->bpb->reserved_sectors * mis_datos->bpb->bytes_sector;
    mis_datos->clusters_offset = mis_datos->fat_offset + (mis_datos->bpb->fat_amount * mis_datos->bpb->sectors_per_fat * mis_datos->bpb->bytes_sector);
    mis_datos->cluster_size = mis_datos->bpb->sectors_cluster*mis_datos->bpb->bytes_sector;
    mis_datos->num_entries = mis_datos->cluster_size / sizeof(struct directory_entry);
    unsigned int clusters = (mis_datos->bpb->bytes_sector*mis_datos->bpb->sectors_per_fat)/4;
    float fssize = ((float)(clusters*mis_datos->bpb->bytes_sector*mis_datos->bpb->sectors_cluster))/1000000;
    float freefssize = ((float)(mis_datos->fsis->free_clusters*mis_datos->bpb->bytes_sector*mis_datos->bpb->sectors_cluster))/1000000;
    fprintf(stderr,"-----------------\n");
    fprintf(stderr," FATs #:       0x%05x = %d\n",mis_datos->bpb->fat_amount,mis_datos->bpb->fat_amount);
    fprintf(stderr," 1st FAT off:  0x%05x = %d\n",mis_datos->fat_offset,mis_datos->fat_offset);
    fprintf(stderr," FAT size(sec):0x%05x = %d\n",mis_datos->bpb->sectors_per_fat,mis_datos->bpb->sectors_per_fat);
    fprintf(stderr," Clusters #:   0x%05x = %d\n",clusters,clusters);
    fprintf(stderr," Clusters off: 0x%05x = %d\n",mis_datos->clusters_offset,mis_datos->clusters_offset);
    fprintf(stderr," Cluster size: 0x%05x = %d\n",mis_datos->cluster_size,mis_datos->cluster_size);
    fprintf(stderr," Sector size : 0x%05x = %d\n",mis_datos->bpb->bytes_sector,mis_datos->bpb->bytes_sector);
    fprintf(stderr," Root Cluster: 0x%05x = %d\n",mis_datos->bpb->root_cluster_number,mis_datos->bpb->root_cluster_number);
    fprintf(stderr," num_entries:  0x%05x = %d\n",mis_datos->num_entries,mis_datos->num_entries);
    fprintf(stderr," - Info in FS info sector:\n");
    fprintf(stderr,"   free_clusters:     0x%05x = %d\n",mis_datos->fsis->free_clusters,mis_datos->fsis->free_clusters);
    fprintf(stderr,"   last_used_cluster: 0x%05x = %d\n",mis_datos->fsis->last_used_cluster,mis_datos->fsis->last_used_cluster);
    fprintf(stderr," FS total : %.2fMB\n",fssize);
    fprintf(stderr," FS free  : %.2fMB\n",freefssize);
    
    fprintf(stderr,"-----------------\n");
    
    mis_datos->st_uid = getuid(); // The owner of the file/directory is the user who mounted the filesystem
    mis_datos->st_gid = getgid(); // The group of the file/directory is the same as the group of the user who mounted the filesystem
    mis_datos->st_atime = time( NULL ); // The last "a"ccess of the file/directory is right now
    mis_datos->st_mtime = time( NULL ); // The last "m"odification of the file/directory is right now
    mis_datos->st_ctime = time( NULL ); // The last "m"odification of the file/directory is right now

    return mis_datos;
}

///***************************************************
/// esta función sólo funciona para el primer cluster de un directorio, 
/// habría que ampliarla para continuar leyendo los siguientes clusters (si los hay)
static int FAT32_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info* fi)
{
    struct structura_mis_datos *mis_datos= (struct structura_mis_datos *) fuse_get_context()->private_data;
    int cluster;
    //encuentra entrada para este directorio
    struct directory_entry *dir_entry = encuentra_entrada((char *)path,mis_datos);
    if (dir_entry==NULL) return -ENOENT;
    struct directory_entry *entry_ptr;
    //leemos cluster del directorio
    cluster = ((dir_entry->First_Cluster_High<<16)|dir_entry->First_Cluster_Low);
    fprintf(stderr,"- PATH: %s - cluster: %d\n",path, cluster);
    char *cluster_buffer = (char*)malloc(mis_datos->cluster_size);
    readCLUSTER(cluster, cluster_buffer, mis_datos);
    //busca en todas las entradas del directorio
    while((cluster & FIN) != FIN){
		for(int i = 0; i < mis_datos->num_entries; i ++)
		{
			entry_ptr= (struct directory_entry*) (cluster_buffer + (sizeof(struct directory_entry) * i));
			fprintf(stderr,"- Entrada %d , attr: 0x%02x, > %s\n",i,entry_ptr->Attributes, entry_ptr->Short_Filename);
			if(entrada_vacia(entry_ptr)) break; // se terminó porque la entrada está vacía
			// asegurarnos de que es una entrada no borrada y no es extensión de nombre
			//En vez de ATTR_DELETE PONGO -27
			if(entry_ptr->Short_Filename[0]!=-27 && !(entry_ptr->Attributes & ATTR_VOLUME_ID) && (entry_ptr->Attributes != ATTR_LONG_NAME))
			{
				char *name = get_long_filename(cluster_buffer, i);
				if(filler(buf, name, NULL, 0)!=0) return -ENOMEM;
				fprintf(stderr,"Nombre del fichero que se mete en buffer: %s\n",name);
				free(name);
			}
		}
		cluster = readFAT(cluster,mis_datos);
		readCLUSTER(cluster, cluster_buffer, mis_datos);
		fprintf(stderr,"Siguiente cluster: %d\n",cluster);		
	}
    free(cluster_buffer);
    return 0;
}

///***************************************************
//Poner por defecto los tres permisos y si es solo lectura quitar escritura.
// Aqui no deberia de ver los permisos y concederlos en funcion de lo que tengan en fat32: Hidden, no mostrar; ReadOnly,solo lectura;Otro,lectura y escritura;
static int FAT32_getattr(const char *path, struct stat *stbuf)
{
    struct structura_mis_datos *mis_datos= (struct structura_mis_datos *) fuse_get_context()->private_data;
    if ( strcmp( path, "/" ) == 0 )
    {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 3;
        stbuf->st_size = mis_datos->cluster_size;
        // para los tamaños de directorio:
        // debería extraerse del tamaño en clusters del directorio?
        // o deberíamos usar el número de entradas realmente ocupadas?
        stbuf->st_blocks = stbuf->st_size/512 + (stbuf->st_size%512)? 1 : 0;
        fprintf(stderr,"- ATTR found for path: %s\n",path);
        // usamos usuario del proceso fuse
        stbuf->st_uid = mis_datos->st_uid;
        stbuf->st_gid = mis_datos->st_gid;
        // usamos fecha de montaje
        stbuf->st_atime = mis_datos->st_atime;
        stbuf->st_mtime = mis_datos->st_mtime;
        stbuf->st_ctime = mis_datos->st_ctime;
        return 0;
    }
    else
    {
        struct directory_entry *dir_entry = encuentra_entrada((char *)path, mis_datos);
        if(dir_entry != NULL) {
            fprintf(stderr,"- ATTR found for path: %s\n",path);

            if(dir_entry->Attributes & ATTR_DIRECTORY)
            {
                stbuf->st_mode = S_IFDIR | 0555;

                stbuf->st_nlink = 2;
                stbuf->st_size = mis_datos->cluster_size;
            }
            else
            {
				if(dir_entry->Attributes & ATTR_READ_ONLY){
                stbuf->st_mode = S_IFREG | 0555;
				}else{
					stbuf->st_mode = S_IFREG | 0777;
				}

                stbuf->st_nlink = 1;
                stbuf->st_size = dir_entry->Filesize;
            }
            // usamos usuario del proceso fuse
            stbuf->st_uid = mis_datos->st_uid;
            stbuf->st_gid = mis_datos->st_gid;
            // traducimos fechas fat32 -> linux
            // puede que no estemos teniendo en cuenta la zona horaria?
            stbuf->st_atime = conv_time(dir_entry->Last_Access_Date, 0);
            stbuf->st_ctime = conv_time(dir_entry->Create_Date, dir_entry->Create_Time);
            stbuf->st_mtime = conv_time(dir_entry->Last_Modified_Date, dir_entry->Last_Modified_Time);

            stbuf->st_blocks = stbuf->st_size/512 + (stbuf->st_size%512)? 1 : 0;
            return 0;
        }

    }

    return -ENOENT;
}

static int FAT32_open(const char *path, struct fuse_file_info *fi)
{
	
    struct structura_mis_datos* mis_datos = (struct structura_mis_datos*)fuse_get_context()->private_data;
    
    struct directory_entry *dir_entry = encuentra_entrada((char *)path, mis_datos);
    
    if(dir_entry->Attributes & ATTR_READ_ONLY){
		if ((fi->flags & 3) != O_RDONLY) return -EACCES;
	}
	
    fi->fh=((dir_entry->First_Cluster_High<<16)|(dir_entry->First_Cluster_Low));
    if(fi->fh<0) return -errno;
    return 0 ;
}


static int FAT32_read(const char *path, char *buf, size_t size, off_t offset,
                        struct fuse_file_info *fi)
{
	struct structura_mis_datos* mis_datos = (struct structura_mis_datos*)fuse_get_context()->private_data;
	int next = fi->fh;
	int cap = mis_datos->cluster_size;
	int leido = 0;
	
	
	char* texto = (char*)malloc(mis_datos->cluster_size);
	strcpy(buf,"");
	
	while(leido!=size && (next&FIN) != FIN){
		if(cap<=offset){
			offset -= cap;
		}else if(cap-offset <= size-leido){
			pread(mis_datos->fh, (void*) texto, cap-offset, mis_datos->clusters_offset + (next- mis_datos->bpb->root_cluster_number)* mis_datos->cluster_size +offset);
			strcat(buf,texto);
			leido+=cap-offset;
			offset = 0;
		}else{
			pread(mis_datos->fh, (void*) texto, mis_datos->cluster_size - offset + size - leido, mis_datos->clusters_offset + (next- mis_datos->bpb->root_cluster_number)* mis_datos->cluster_size +offset);
			leido += cap - offset -size +leido;
			strcat(buf,texto);
		}
		next = readFAT(next,mis_datos);
	}
	free(texto);
	return leido;
}


//Esta haciendo cosillas raras a la hora de escribir en varios clusters
static int FAT32_write(const char *path, const char *buffer, size_t size, off_t offset, struct fuse_file_info * fi){
	
	struct structura_mis_datos* mis_datos = (struct structura_mis_datos*)fuse_get_context()->private_data;
	int next = fi->fh;
	int cap = mis_datos->cluster_size;
	int posicion = encuentrapos((char *)path,mis_datos) + 28;
	
	//Leemos el tamaño del fichero y le sumamos el size - 1
	int tam_ant = 0;
	pread(mis_datos->fh, &tam_ant, 4, posicion);
	fprintf(stderr,"TAM antiguo: %i\n", tam_ant);
	//Si escribimos en medio nos olvidamos del resto del archivo;
	if(tam_ant>offset) tam_ant = tam_ant-offset;
	tam_ant = tam_ant + size;
	fprintf(stderr,"TAM nuevo: %i,size añadido: %li\n", tam_ant,size);
	pwrite(mis_datos->fh, &tam_ant, 4, posicion);
	
	
//Cambiamos la FAT:

	int numero_Clusters = tam_ant/cap;
	//Si ocpa uno y medio le ponemos 2 clusters
	if((tam_ant%cap)!= 0) numero_Clusters++;
	int next2 = next;
	int next_ant = FIN;
	fprintf(stderr,"numClus: %i\n",numero_Clusters);
	for (int i=1;i<numero_Clusters;i++){
		next_ant = next2;
		next2 = readFAT(next2,mis_datos);
		if((next2&FIN) == FIN || next2 == 0){
			fprintf(stderr,"Nuevo cluster adjudicado\n");
			next2 = encontrarPosLibre(mis_datos);
			//Escribir En la parte de la fat que indica next_ant el valor de next2
			writeFAT(next_ant,next2,mis_datos);
		}
		if(i == numero_Clusters-1){
			fprintf(stderr,"Marca final\n");
			next_ant = readFAT(next2,mis_datos);
			//Escribir en la parte de la FAT de next2 FIN
			writeFAT(next2,FINCLUS,mis_datos);
		}
	}
	while((next_ant&FIN)!=FIN && next_ant != 0){
		fprintf(stderr,"Libera el cluster: \n");
		next2 = next_ant;
		next_ant = readFAT(next_ant,mis_datos);
		//Ponemos un 0 en la Fat de next2;
		writeFAT(next2,0,mis_datos);
	}
	
//Fin cambiar FAT


	const char* texto = (char*)malloc(mis_datos->cluster_size);
	texto = buffer;
	int escrito=0;
	
	while((next&FIN)!=FIN){
		if(offset>=cap){
			fprintf(stderr,"1\n");
			offset-=cap;
		}else{
			fprintf(stderr,"2\n");
			texto = buffer + escrito;
			pwrite(mis_datos->fh, (void*) texto, cap-offset, mis_datos->clusters_offset + (next- mis_datos->bpb->root_cluster_number)* cap +offset);
			escrito = cap-offset;
			offset = 0;
		}
		fprintf(stderr,"4\n");
		next = readFAT(next,mis_datos);
	}
    return size;
}

static int FAT32_truncate (const char *path,off_t offset)
{
	struct structura_mis_datos* mis_datos = (struct structura_mis_datos*)fuse_get_context()->private_data;
	//encuentra pos y encuentra entrada modifican el path, y luego pasa el path de mala manera al write, asique creamos char auxiliar
	//para que no pete.
	char conspiracion[strlen(path+1)];
	strcpy(conspiracion, path);
	int cap = mis_datos->cluster_size;
	int posicion = encuentrapos((char *)conspiracion,mis_datos) + 28;
	
	int tam_nuevo = offset;
	pwrite(mis_datos->fh, &tam_nuevo, 4, posicion);
	
	//No modifico el numero de cluster, porque cuando escribimos estos se modifican por si solos.
	return offset;
}

//NO DEBE DEJAR BORRAR SI TIENE CONTENIDOS.
static int FAT32_rmdir(const char* path)
{
	
	struct structura_mis_datos* mis_datos = (struct structura_mis_datos*)fuse_get_context()->private_data;
	int pos = encuentrapos((void*)path,mis_datos);
	
	
	//Borramos solamente si esta vacio, es decir solo contiene el dir . y el ..;
    int cluster;
    //encuentra entrada para este directorio
    struct directory_entry *dir_entry = encuentra_entrada((char *)path,mis_datos);
    if (dir_entry==NULL) return -ENOENT;
    struct directory_entry *entry_ptr;
    //leemos cluster del directorio
    int alto,bajo;alto = 0;bajo =0;
	pread(mis_datos->fh,&alto,2,pos + 20);
	pread(mis_datos->fh,&bajo,2,pos + 26);
    cluster = ((alto<<16)|bajo);
    int cluster_aux = cluster;
    fprintf(stderr,"RMDIR-Cluster INICIAL: %i\n",cluster);
    char *cluster_buffer = (char*)malloc(mis_datos->cluster_size);
    readCLUSTER(cluster, cluster_buffer, mis_datos);
    //busca en todas las entradas del directorio
    while((cluster & FIN) != FIN){
		for(int i = 0; i < mis_datos->num_entries; i ++)
		{
			entry_ptr= (struct directory_entry*) (cluster_buffer + (sizeof(struct directory_entry) * i));
			fprintf(stderr,"- Entrada %d , attr: 0x%02x, > %s\n",i,entry_ptr->Attributes, entry_ptr->Short_Filename);
			if(entrada_vacia(entry_ptr)) break; // se terminó porque la entrada está vacía
			// asegurarnos de que es una entrada no borrada y no es extensión de nombre
			//En vez de ATTR_DELETE PONGO -27
			if(entry_ptr->Short_Filename[0]!=-27 && !(entry_ptr->Attributes & ATTR_VOLUME_ID) && (entry_ptr->Attributes != ATTR_LONG_NAME))
			{
				char *name = get_long_filename(cluster_buffer, i);
				fprintf(stderr,"Nombre del fichero que se mete en buffer: %s\n",name);
				//SI NO ES . O .. DEVOLVER 0
				if(strncmp(name,".",1) && strncmp(name,"..",2)){
					free(name);
					return 0;
				}
				
			}
		}
		cluster = readFAT(cluster,mis_datos);
		readCLUSTER(cluster, cluster_buffer, mis_datos);	
	}
    free(cluster_buffer);
    
    
    cluster = cluster_aux;
    //Ponemos todos sus clusters a 0
	while((cluster&FIN) != FIN){
		cluster_aux = cluster;
		cluster = readFAT(cluster,mis_datos);
		writeFAT(cluster_aux,0,mis_datos);
	}
    
    //Ponemos su entrada borrada.
	int num = ATTR_DELETED;
	pwrite(mis_datos->fh,&num,1,pos);
	return 0;
}


static int FAT32_unlink(const char* path){
	
	struct structura_mis_datos* mis_datos = (struct structura_mis_datos*)fuse_get_context()->private_data;
	int pos = encuentrapos((void*)path,mis_datos);
	
	//Inicializo a cero que si no puede dar problemas.
	int alto,bajo;alto = 0;bajo = 0;
	pread(mis_datos->fh,&alto,2,pos + 20);
	pread(mis_datos->fh,&bajo,2,pos + 26);
	
    int cluster = ((alto<<16)|bajo);
	int cluster2;
	
	//ponemos suus clusters a 0
	while((cluster&FIN) != FIN){
		cluster2 = cluster;
		cluster = readFAT(cluster,mis_datos);
		writeFAT(cluster2,0,mis_datos);
	}
	
	//Ponemos su entrada borrada.
	int num = ATTR_DELETED;
	pwrite(mis_datos->fh,&num,1,pos);
	return 0;
}


/***********************************
 * operaciones FUSE
 * */
static struct fuse_operations basic_oper = {
    .init       = FAT32_init,
    .getattr	= FAT32_getattr,
    .readdir	= FAT32_readdir,
    .open		= FAT32_open,
    .read		= FAT32_read,
    .write		= FAT32_write,
    .truncate	= FAT32_truncate,
    .rmdir		= FAT32_rmdir,
    .unlink		= FAT32_unlink,
};


/***********************************
 * */
int main(int argc, char *argv[])
{
    struct structura_mis_datos *mis_datos;

    mis_datos=malloc(sizeof(struct structura_mis_datos));

    // análisis parámetros de entrada
    if ((argc < 3) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-'))
    {
        printf("Error en los parámetros\n");
    };

    mis_datos->fichero_imagen = strdup(argv[argc-2]); // fichero donde está la imagen FAT32

    mis_datos->fh=open(mis_datos->fichero_imagen, O_RDWR);

    if(mis_datos->fh<0)
    {
        perror("Error al abrir el fichero");
        exit(-1);
    }

    argv[argc-2] = argv[argc-1];
    argv[argc-1] = NULL;
    argc--;

    return fuse_main(argc, argv, &basic_oper, mis_datos);
}
