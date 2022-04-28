#include "file_reader.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
int bits_per_fat_entry = (235940 % 2 == 1) ? 12 : 16;

uint16_t *get_chain_fat16(const void * const buffer, size_t size, uint16_t first_cluster)
{
    if(!buffer || size < 1)    return NULL;
    uint16_t *fat = (uint16_t *)buffer;
    uint16_t temp = *(fat + first_cluster);
    uint16_t cluster_count = 1;
    size_t safe = 0;
    while(temp < 0xFFF8 && safe < size)
    {
        cluster_count++;
        temp = *(fat + temp);
        safe++;
    }
    uint16_t *ret = malloc(cluster_count * 2);
    if(!ret)    return NULL;
    *(ret) = first_cluster;
    temp = *(fat + first_cluster);
    for(size_t i = 1 ; i < cluster_count ; i++)
    {
        *(ret + i) = temp;
        temp = *(fat + temp);
    }
    return ret;
}
chain *get_chain_fat12(const void * const buffer, size_t size, uint16_t first_cluster)
{
    if(!buffer || size < 1 || first_cluster < 2)    return NULL;
    chain *ret = malloc(sizeof(chain));
    if(!ret)    return NULL;
    uint16_t value = first_cluster;
    uint16_t *fat = (uint16_t *)buffer;
    size_t cluster_count = 0;
    size_t safe = 0;
    uint8_t left,right;
    do
    {
        cluster_count++;
        safe++;
        if(value % 2 == 0)
        {
            left = *((uint8_t *)fat + (int)(value * 3/2 ));
            right = *((uint8_t *)fat + (int)(value * 3/2 + 1));
            value = ((0x0f & right) << 8) | left;
        }
        else
        {
            left = *((uint8_t *)fat + (int)(value * 3/2 ));
            right = *((uint8_t *)fat + (int)(value * 3/2 + 1));
            value = right << 4 | ((0xf0 & left) >> 4);
        }
    }while(value < 0xff8 && safe < size);
    ret->size = cluster_count;
    ret->clusters = malloc(cluster_count * sizeof(uint16_t));
    if(!ret->clusters)
    {
        free(ret);
        return NULL;
    }
    *(ret->clusters) = first_cluster;
    value = (first_cluster);
    for(size_t i = 1 ; i < cluster_count ; i++)
    {
        if(value % 2 == 0)
        {
            left = *((uint8_t *)fat + (int)(value * 3/2));
            right = *((uint8_t *)fat + (int)(value * 3/2 + 1));
            value = ((0x0f & right) << 8) | left;
        }
        else
        {
            left = *((uint8_t *)fat + (int)(value * 3/2));
            right = *((uint8_t *)fat + (int)(value * 3/2 + 1));
            value = right << 4 | ((0xf0 & left) >> 4);
        }
        *(ret->clusters + i) =  value;
    }
    return ret;
}

long position = 0;
char name[20] = {'\0'};
char *remove_spaces(char *str)
{
    int i = 0, j = 0;
    while (str[i])
    {
        if (str[i] != ' ' && str[i]!='\n')  str[j++] = str[i];
        i++;
    }
    str[j] = '\0';
    return str;
}
void makename_dot(char *res, char *left, char *right)
{
    left = remove_spaces(left);
    right = remove_spaces(right);
    strcat(res,left);
    if(strlen(right) > 0)   strcat(res,".");
    strcat(res,right);
}

uint16_t get_day(uint16_t in) {return in & 0x1F;}
uint16_t get_month(uint16_t in) {return (in & 0x1E0) >> 5;}
uint16_t get_year(uint16_t in) {return 1980 + ((in & 65024) >> 9);}
uint16_t get_hour(uint16_t in) {return (in & 0xF800) >> 11;}
uint16_t get_minute(uint16_t in) {return (in & 0x7E0) >> 5;}
uint16_t get_second(uint16_t in) {return in & 0x1F;}


struct disk_t* disk_open_from_file(const char* volume_file_name)
{
    if(!volume_file_name)
    {
        errno = EFAULT;
        return NULL;
    }
    FILE *f = fopen(volume_file_name,"r");
    if(!f)
    {
        errno = ENOENT;
        return NULL;
    }
    disk_t *dysk = malloc(sizeof (disk_t));
    if(!dysk)
    {
        errno = ENOMEM;
        fclose(f);
        return NULL;
    }
    dysk->f = f;
    return dysk;
}
int disk_read(struct disk_t* pdisk, int32_t first_sector, void* buffer, int32_t sectors_to_read)
{
    if(!pdisk || !pdisk->f || first_sector < 0 || !buffer || sectors_to_read < 0)
    {
        errno = EFAULT;
        return -1;
    }
    fseek(pdisk->f, first_sector * 512, SEEK_SET);
    if(!fread(buffer,1,512 * sectors_to_read,pdisk->f))
    {
        errno = ERANGE;
        return -1;
    }
    return 0;
}
int disk_close(struct disk_t* pdisk)
{
    if(!pdisk || !pdisk->f)
    {
        errno = EFAULT;
        return -1;
    }
    fclose(pdisk->f);
    return 0;
}

struct volume_t* fat_open(struct disk_t* pdisk, uint32_t first_sector)
{
    if(!pdisk || !pdisk->f)
    {
        errno = EFAULT;
        return NULL;
    }
    struct volume_t *vol = malloc(sizeof (struct volume_t));
    if(!vol)
    {
        errno = ENOMEM;
        free(pdisk);
        return NULL;
    }
    vol->super = malloc(sizeof(fat_super_t));
    if(!vol->super)
    {
        free(vol);
        free(pdisk);
        errno = ENOMEM;
        return NULL;
    }
    disk_read(pdisk,(int32_t)first_sector,vol->super,1);
    if(vol->super->bytes_per_sector == 0)
    {
        errno = EINVAL;
        free(vol->super);
        free(vol);
        free(pdisk);
        return NULL;
    }

    vol->total_sectors = (vol->super->logical_sectors == 0)? vol->super->logical_sectors32 : vol->super->logical_sectors;
    vol->fat_size = vol->super->sectors_per_fat;
    vol->disk = pdisk;
    vol->root_dir_sectors = ((vol->super->root_dir_capacity * 32) + (vol->super->bytes_per_sector - 1)) / vol->super->bytes_per_sector;
    vol->first_data_sector = vol->super->reserved_sectors + (vol->super->fat_count * vol->fat_size) + vol->root_dir_sectors;
    vol->first_fat_sector = vol->super->reserved_sectors;
    vol->data_sectors = vol->super->logical_sectors - (vol->super->reserved_sectors + (vol->super->fat_count * vol->fat_size) + vol->root_dir_sectors);
    vol->total_clusters = vol->data_sectors / vol->super->sectors_per_cluster;
    vol->first_root_dir_sector = vol->first_data_sector - vol->root_dir_sectors;


    uint16_t *buf1 = malloc(vol->fat_size * 512);
    uint16_t *buf2 = malloc(vol->fat_size * 512);

    disk_read(pdisk,vol->first_fat_sector,buf1,vol->super->sectors_per_fat);
    disk_read(pdisk,vol->first_fat_sector + (vol->super->sectors_per_fat),buf2,vol->super->sectors_per_fat);
    if(memcmp(buf1,buf2,vol->fat_size))
    {
        free(buf1);
        free(pdisk);
        free(buf2);
        free(vol->super);
        free(vol);
        errno = EINVAL;
        return NULL;
    }
    vol->fat = buf1;
    free(buf2);
    vol->root = malloc(vol->super->root_dir_capacity * 32);
    if(!vol->root)
    {
        free(vol->fat);
        free(vol->super);
        free(vol);
        errno = ENOMEM;
        return NULL;
    }
    disk_read(pdisk,vol->first_root_dir_sector,vol->root,vol->root_dir_sectors);
    return vol;
}
int fat_close(struct volume_t* pvolume)
{
    if(!pvolume)
    {
        errno = EFAULT;
        return -1;
    }
    if(pvolume->fat)    free(pvolume->fat);
    if(pvolume->disk)    free(pvolume->disk);
    if(pvolume->super)    free(pvolume->super);
    if(pvolume->root)   free(pvolume->root);
    free(pvolume);
    return 0;
}

struct dir_entry_t *find_entry(const char* filename, struct dir_entry_t *entries, uint16_t count)
{
    char buf[12];
    char left[9];
    char right[4];
    for(uint16_t i = 0 ; i < count ; i++)
    {
        for(int j = 0 ; j < 12 ; j++)   buf[j] = '\0';
        for(int j = 0 ; j < 9 ; j++)   left[j] = '\0';
        for(int j = 0 ; j < 4 ; j++)   right[j] = '\0';
        memcpy(left,entries[i].name,8);
        memcpy(right,entries[i].name + 8,3);
        makename_dot(buf,left,right);
        if(strcmp(buf,filename) == 0)   return entries + i;
    }
    return NULL;
}
uint16_t get_next(struct volume_t *buffer, uint16_t active_cluster)
{
    unsigned char FAT_table[512];
    unsigned int fat_offset = active_cluster * 2;
    unsigned int fat_sector = buffer->first_fat_sector + (fat_offset / buffer->super->bytes_per_sector);
    unsigned int ent_offset = fat_offset % buffer->super->bytes_per_sector;

    disk_read(buffer->disk,(int32_t)fat_sector,FAT_table,1);

    unsigned short table_value = *(unsigned short*)&FAT_table[ent_offset];
    return table_value;
}

uint16_t *better_getchain(struct volume_t *buffer, size_t size, uint16_t first_cluster)
{
    uint16_t *res = calloc(size,1);
    uint16_t value = first_cluster;
    for(size_t i = 0 ; i < size ; i++)
    {
        res[i] = value;
        printf("Cluster %ld: %d\n",i,res[i]);
        value = get_next(buffer,value);
        if(value >= 0xFFF8) break;
    }
    return res;
}
struct file_t* file_open(struct volume_t* pvolume, const char* file_name)
{
    if(!pvolume || !file_name)
    {
        errno = EFAULT;
        return NULL;
    }
    struct file_t *file = malloc(sizeof(struct file_t));
    if(!file)
    {
        errno = ENOMEM;
        return NULL;
    }
    struct dir_entry_t *entry = find_entry(file_name,pvolume->root,pvolume->super->root_dir_capacity);
    if(!entry)
    {
        printf("\nDIDNT FIND ENTRY\n");
        errno = ENOENT;
        free(file);
        return NULL;
    }
    if(entry->at.is_directory || entry->at.is_volume)
    {
        errno = EISDIR;
        free(file);
        return NULL;
    }
    file->clusters = better_getchain(pvolume,pvolume->fat_size, entry->low_16);
    if(!file->clusters)
    {
        free(file);
        errno = ENOMEM;
        return NULL;
    }
    file->offset = 0;
    file->size = entry->size;
    file->vol = pvolume;
    return file;
}
int file_close(struct file_t* stream)
{
    if(!stream)
    {
        errno = EFAULT;
        return -1;
    }
    free(stream->clusters);
    free(stream);
    return 0;
}
size_t file_read(void *ptr, size_t size, size_t nmemb, struct file_t *stream)
{
    if(!ptr || !stream)
    {
        errno = EFAULT;
        return -1;
    }
    if(stream->offset  >= stream->size)  return 0;
    unsigned char buffer[4096];
    size_t block_size = stream->vol->super->sectors_per_cluster * stream->vol->super->bytes_per_sector;
    uint16_t eval;
    if(nmemb * size > stream->size)
    {
        if(size <= stream->size) nmemb = stream->size/size;
        else    return 0;
    }
    uint16_t data_left = nmemb * size;
    if(stream->offset + data_left > stream->size)
    {
        data_left = stream->size - stream->offset;
    }
    uint16_t return_value = 0 ;
    uint16_t able;
    uint16_t final;
    while(1)
    {
        if(stream->offset == stream->size)  break;
        disk_read(stream->vol->disk, stream->clusters[stream->offset/block_size] * stream->vol->super->sectors_per_cluster + stream->vol->first_data_sector - 2 * stream->vol->super->sectors_per_cluster,buffer,stream->vol->super->sectors_per_cluster);
        if(data_left >= block_size) eval = block_size;
        else eval = data_left;
        able = block_size - (stream->offset % block_size);
        if(able > eval) final = eval;
        else final = able;
        memcpy(((char*)ptr + return_value),buffer + stream->offset%block_size,final);
        return_value += final;
        data_left -= final;
        stream->offset += final;
        if(data_left == 0)  break;
    }
    return return_value/size;
}

int32_t file_seek(struct file_t* stream, int32_t offset, int whence)
{
    if(!stream)
    {
        errno = EFAULT;
        return -1;
    }
    if(whence == SEEK_SET)
    {
        if((size_t)offset >= stream->size || offset < 0)
        {
            errno = ENXIO;
            return -1;
        }
        stream->offset = offset;
    }
    else if(whence == SEEK_CUR)
    {
        if(stream->offset + offset < 0 || stream->offset + (size_t)offset > stream->size)
        {
            errno = ENXIO;
            return -1;
        }
        stream->offset += offset;
    }
    else if(whence == SEEK_END)
    {
        if(offset > 0 || (-1 * offset) >= (int)stream->size)
        {
            errno = ENXIO;
            return -1;
        }
        stream->offset = stream->size + offset;
    }
    else
    {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

struct dir_t* dir_open(struct volume_t* pvolume, const char* dir_path)
{
    if(!pvolume || !dir_path || strcmp(dir_path,"\\"))
    {
        errno = EFAULT;
        return NULL;
    }
    struct dir_t *dir_handle = malloc(sizeof(struct dir_t));
    if(!dir_handle)
    {
        errno = ENOMEM;
        return NULL;
    }
    dir_handle->directories = pvolume->root;
    dir_handle->all = pvolume->super->root_dir_capacity;
    dir_handle->current = 0;
    return dir_handle;
}
int dir_read(struct dir_t* pdir, struct dir_entry_t* pentry)
{
    if(!pdir || !pentry)
    {
        errno = EFAULT;
        return -1;
    }
    if(pdir->current >= pdir->all)
    {
        errno = ENXIO;
        return 1;
    }
    *pentry = pdir->directories[pdir->current];
    while( pentry->at.is_volume == 1 || !isalpha(pentry->name[0]))
    {
        pdir->current++;
        *pentry = pdir->directories[pdir->current];
        if(pdir->current >= pdir->all)
        {
            errno = ENXIO;
            return 1;
        }
    }
    char *buf = calloc(20,1);
    char left[9];
    char right[4];
    memcpy(left,pentry->name,8);
    memcpy(right,pentry->name + 8,3);
    makename_dot(buf,left,right);
    memcpy(pentry->name,buf,11);
    *(pentry->name + 11) = '\0';
    free(buf);
    pdir->current ++;
    return 0;
}
int dir_close(struct dir_t* pdir)
{
    if(!pdir || !pdir->directories)
    {
        errno = EFAULT;
    }
    free(pdir);
    return 0;
}





