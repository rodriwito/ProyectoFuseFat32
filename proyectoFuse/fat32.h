#ifndef _FAT32_H_
#define _FAT32_H_

#include <stdint.h>

struct bios_param_block {
    int8_t	  jmp_boot[3];
    char	  oemname[8];
    int16_t   bytes_sector;               //bytes_per_sector
    int8_t    sectors_cluster;            //sectors_per_cluster
    int16_t   reserved_sectors;           //reserved_logical_sectors
    int8_t    fat_amount;                 //file_allocation_tables_amount
    int16_t   max_root_directory_entries;
    int16_t   total_logical_sectors;
    uint8_t   media_descriptor;
    int16_t   logical_sectors_per_fat;
    int16_t   sectors_per_track;
    int16_t   number_of_heads;
    int32_t   hidden_sectors;
    int32_t   total_logical_sectors_2;
    int32_t   sectors_per_fat;
    int16_t   drive_description;
    int16_t   file_system_version;
    int32_t   root_cluster_number;
} __attribute__ ((__packed__));// no Padding


struct fs_information_sector {
    char      signature1[4]; // Should be (0x52 0x52 0x61 0x41 = "RRaA")
    char      reserved1[480];
    char	  signature2[4]; // should be (0x72 0x72 0x41 0x61 = "rrAa")
    uint32_t  free_clusters;
    uint32_t  last_used_cluster;
    char	  reserved2[12];
    char      end_signature[4]; // should be (0x00 0x00 0x55 0xAA)
} __attribute__ ((__packed__));// no Padding

struct directory_entry {
    char    Short_Filename[8];
    char    Short_File_Extension[3];

    /*
      Attribute Bits:
      0:    read only
      1:    hidden      -   Shouldn't show in Dir listing
      2:    system      -   Belongs to system, shouldn't be moved
      3:    volume id   -   Filename is volume label
      4:    directory   -   Is a Subdirectory
      5:    archive     -   Has been changed since last backup, ignore
      6-7:  unused, should be 0
    */
    uint8_t  Attributes;
    uint8_t  Extended_Attributes;

    /*
      Bits 15-11:   Hours   (0-23)
      Bits 10-5:    Minutes (0-59)
      Bits 4-0:     Seconds (0-29) - Only recorded to a 2 second resolution
    */
    int8_t  Create_Time_Finer;
    int16_t Create_Time;

    /*
      Bits 15-9:    Year    (0 = 1980)
      Bits 8-5:     Month   (1-12)
      Bits 4-0:     Day     (1-31)
    */
    int16_t Create_Date;
    int16_t Last_Access_Date; 
    int16_t First_Cluster_High;
    int16_t Last_Modified_Time; 
    int16_t Last_Modified_Date;
    int16_t First_Cluster_Low;
    int32_t Filesize;
}  __attribute__ ((__packed__)); // no Padding

struct long_filename_entry {
    uint8_t   sequence_number;
    uint8_t   name_1[10];
    uint8_t   attribute;      //Always 0x0F
    uint8_t   type;
    uint8_t   checksum;
    uint8_t   name_2[12];
    uint16_t  first_cluster;  //Always 0x0;
    uint8_t   name_3[4];
} __attribute__ ((__packed__)); // no Padding


struct structura_mis_datos {
    char *fichero_imagen;
    int fh;
    struct bios_param_block *bpb;
    struct fs_information_sector * fsis;
    int fat_offset;       // comienzo de la FAT
    int clusters_offset;  // comienzo de los datos
    int cluster_size;     // tamaño cluster en bytes
    int num_entries;      // numero de entradas de directorio en un cluster
    struct timespec st_atim;  	/* fechas */
    struct timespec st_mtim;
    struct timespec st_ctim;
    uid_t     st_uid;        	/* El usuario y grupo */
    gid_t     st_gid;

};

// directory entry attributes:
#define ATTR_READ_ONLY 0x01
#define ATTR_HIDDEN 0x02
#define ATTR_SYSTEM 0x04
#define ATTR_VOLUME_ID 0x08
#define ATTR_DIRECTORY 0x10
#define ATTR_ARCHIVE 0x20
#define ATTR_LONG_NAME 0x0F
#define ATTR_DELETED 0xE5   // al principio del nombre

#endif
