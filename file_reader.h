#pragma once
#include <stdio.h>
#include <stdint-gcc.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define FILE_UNALLOCATED 0x00
#define FILE_DELETED 0xe5

typedef struct clusters_chain_t {
    uint16_t *clusters;
    size_t size;
}chain;

typedef union{
    uint16_t value;
    char bits[16];
}bitfield_16;

typedef union
{
    uint8_t byte;
    char bits[8];
}bitfield_8;

typedef struct
{
    unsigned char is_readonly:1;
    unsigned char is_hidden:1;
    unsigned char is_system:1;
    unsigned char is_volume:1;
    unsigned char is_directory:1;
    unsigned char is_archived:1;
    unsigned char is_device:1;
    unsigned char is_reserved:1;
}attributes;



struct dir_entry_t
{
    char name[11];
    attributes at;
    uint8_t reserved;
    uint8_t creation_time_tenths;
    uint16_t creation_time;
    uint16_t creation_date;
    uint16_t lat_access_date;
    uint16_t high_16;
    uint16_t modified_time;
    uint16_t modified_date;
    uint16_t low_16;
    uint32_t size;
}__attribute__ ((packed));

typedef struct fat_super_t
{
    uint8_t jump_code[3];
    char oem_name[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t fat_count;
    uint16_t root_dir_capacity;
    uint16_t logical_sectors;
    uint8_t media_type;
    uint16_t sectors_per_fat;
    uint16_t chs_sectors_per_track;
    uint16_t chs_tracks_per_cylinder;
    uint32_t hidden_sectors;
    uint32_t logical_sectors32;
    uint8_t media_id;
    uint8_t chs_head;
    uint8_t ext_bpb_signature;
    uint32_t serial_number;
    char volume_label[11];
    char fsid[8];
    uint8_t boot_code[448];
    uint16_t magic;
}__attribute__((packed)) fat_super_t;

struct volume_t
{
    fat_super_t *super;
    struct disk_t *disk;
    struct dir_entry_t *root;
    uint16_t *fat;
    uint16_t total_sectors;
    int32_t fat_size;
    uint16_t first_root_dir_sector;
    uint16_t root_dir_sectors;
    uint16_t first_data_sector;
    uint16_t first_fat_sector;
    uint32_t data_sectors;
    uint32_t total_clusters;
}__attribute__((packed));

typedef struct disk_t
{
    FILE *f;
}disk_t;

struct file_t
{
    uint16_t *clusters;
    uint16_t offset;
    size_t size;
    struct volume_t *vol;
};

struct dir_t
{
    struct dir_entry_t *directories;
    uint16_t all;
    uint16_t current;
};


uint16_t *get_chain_fat16(const void * const buffer, size_t size, uint16_t first_cluster);
chain *get_chain_fat12(const void * const buffer, size_t size, uint16_t first_cluster);

char* remove_spaces(char* );
void makename(char *res, char *left, char *right);
uint16_t get_day(uint16_t in);
uint16_t get_month(uint16_t in);
uint16_t get_year(uint16_t in);
uint16_t get_hour(uint16_t in);
uint16_t get_minute(uint16_t in);
uint16_t get_second(uint16_t in);

void manage_user_directory_interface(const char* filename);

struct dir_entry_t *read_directory_entry(const char *filename);

struct disk_t* disk_open_from_file(const char* volume_file_name);
int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read);
int disk_close(struct disk_t* pdisk);

struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector);
int fat_close(struct volume_t* pvolume);

struct file_t* file_open(struct volume_t* pvolume, const char* file_name);
int file_close(struct file_t* stream);
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream);
int32_t file_seek(struct file_t* stream, int32_t offset, int whence);

struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path);
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry);
int dir_close(struct dir_t* pdir);