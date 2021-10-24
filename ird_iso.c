#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <malloc.h>
#include <sys/stat.h>
#include <dirent.h>
#include "ird_iso.h"

#if defined (__MSVCRT__)
#define stat _stati64
#endif

#define ISODCL(from, to) (to - from + 1)
#define MAX_ISO_PATHS 4096

#define YES			1
#define NO 			0
#define SUCCESS		1
#define FAILED 		0

#define IRD_FILE_BUFFSIZE 0x20*0x800

#define print_load printf
#define Delete unlink

typedef struct {
    int parent;
    char *name;

} _directory_iso2;

static _directory_iso2 *directory_iso2 = NULL;

typedef struct {
    u32 size;
    char path[0x420];

} _split_file;

static _split_file split_file[64];
static FILE *fp_split = NULL;
static FILE *fp_split0 = NULL;
static int split_index = 0;

static int isonum_731 (unsigned char * p)
{
	return ((p[0] & 0xff)
		| ((p[1] & 0xff) << 8)
		| ((p[2] & 0xff) << 16)
		| ((p[3] & 0xff) << 24));
}

static int isonum_733 (unsigned char * p)
{
	return (isonum_731 (p));
}

static int isonum_721 (char * p)
{
	return ((p[0] & 0xff) | ((p[1] & 0xff) << 8));
}

struct iso_primary_descriptor {
	unsigned char type			[ISODCL (  1,   1)]; /* 711 */
	unsigned char id				[ISODCL (  2,   6)];
	unsigned char version			[ISODCL (  7,   7)]; /* 711 */
	unsigned char unused1			[ISODCL (  8,   8)];
	unsigned char system_id			[ISODCL (  9,  40)]; /* aunsigned chars */
	unsigned char volume_id			[ISODCL ( 41,  72)]; /* dunsigned chars */
	unsigned char unused2			[ISODCL ( 73,  80)];
	unsigned char volume_space_size		[ISODCL ( 81,  88)]; /* 733 */
	unsigned char unused3			[ISODCL ( 89, 120)];
	unsigned char volume_set_size		[ISODCL (121, 124)]; /* 723 */
	unsigned char volume_sequence_number	[ISODCL (125, 128)]; /* 723 */
	unsigned char logical_block_size		[ISODCL (129, 132)]; /* 723 */
	unsigned char path_table_size		[ISODCL (133, 140)]; /* 733 */
	unsigned char type_l_path_table		[ISODCL (141, 144)]; /* 731 */
	unsigned char opt_type_l_path_table	[ISODCL (145, 148)]; /* 731 */
	unsigned char type_m_path_table		[ISODCL (149, 152)]; /* 732 */
	unsigned char opt_type_m_path_table	[ISODCL (153, 156)]; /* 732 */
	unsigned char root_directory_record	[ISODCL (157, 190)]; /* 9.1 */
	unsigned char volume_set_id		[ISODCL (191, 318)]; /* dunsigned chars */
	unsigned char publisher_id		[ISODCL (319, 446)]; /* achars */
	unsigned char preparer_id		[ISODCL (447, 574)]; /* achars */
	unsigned char application_id		[ISODCL (575, 702)]; /* achars */
	unsigned char copyright_file_id		[ISODCL (703, 739)]; /* 7.5 dchars */
	unsigned char abstract_file_id		[ISODCL (740, 776)]; /* 7.5 dchars */
	unsigned char bibliographic_file_id	[ISODCL (777, 813)]; /* 7.5 dchars */
	unsigned char creation_date		[ISODCL (814, 830)]; /* 8.4.26.1 */
	unsigned char modification_date		[ISODCL (831, 847)]; /* 8.4.26.1 */
	unsigned char expiration_date		[ISODCL (848, 864)]; /* 8.4.26.1 */
	unsigned char effective_date		[ISODCL (865, 881)]; /* 8.4.26.1 */
	unsigned char file_structure_version	[ISODCL (882, 882)]; /* 711 */
	unsigned char unused4			[ISODCL (883, 883)];
	unsigned char application_data		[ISODCL (884, 1395)];
	unsigned char unused5			[ISODCL (1396, 2048)];
};

struct iso_directory_record {
	unsigned char length			[ISODCL (1, 1)]; /* 711 */
	unsigned char ext_attr_length		[ISODCL (2, 2)]; /* 711 */
	unsigned char extent			[ISODCL (3, 10)]; /* 733 */
	unsigned char size			[ISODCL (11, 18)]; /* 733 */
	unsigned char date			[ISODCL (19, 25)]; /* 7 by 711 */
	unsigned char flags			[ISODCL (26, 26)];
	unsigned char file_unit_size		[ISODCL (27, 27)]; /* 711 */
	unsigned char interleave			[ISODCL (28, 28)]; /* 711 */
	unsigned char volume_sequence_number	[ISODCL (29, 32)]; /* 723 */
	unsigned char name_len		[1]; /* 711 */
	unsigned char name			[1];
};

struct iso_path_table{
	unsigned char  name_len[2];	/* 721 */
	char extent[4];		/* 731 */
	char  parent[2];	/* 721 */
	char name[1];
};

static void UTF16_to_UTF8(u16 *stw, u8 *stb)
{
    while(SWAP_BE(stw[0])) {
        if((SWAP_BE(stw[0]) & 0xFF80) == 0) {
            *(stb++) = SWAP_BE(stw[0]) & 0xFF;   // utf16 00000000 0xxxxxxx utf8 0xxxxxxx
        } else if((SWAP_BE(stw[0]) & 0xF800) == 0) { // utf16 00000yyy yyxxxxxx utf8 110yyyyy 10xxxxxx
            *(stb++) = ((SWAP_BE(stw[0])>>6) & 0xFF) | 0xC0; *(stb++) = (SWAP_BE(stw[0]) & 0x3F) | 0x80;
        } else if((SWAP_BE(stw[0]) & 0xFC00) == 0xD800 && (SWAP_BE(stw[1]) & 0xFC00) == 0xDC00 ) { // utf16 110110ww wwzzzzyy 110111yy yyxxxxxx (wwww = uuuuu - 1) 
                                                                             // utf8 1111000uu 10uuzzzz 10yyyyyy 10xxxxxx  
																			 *(stb++)= (((SWAP_BE(stw[0]) + 64)>>8) & 0x3) | 0xF0; *(stb++)= (((SWAP_BE(stw[0])>>2) + 16) & 0x3F) | 0x80; 
            *(stb++)= ((SWAP_BE(stw[0])>>4) & 0x30) | 0x80 | ((SWAP_BE(stw[1])<<2) & 0xF); *(stb++)= (SWAP_BE(stw[1]) & 0x3F) | 0x80;
            stw++;
        } else { // utf16 zzzzyyyy yyxxxxxx utf8 1110zzzz 10yyyyyy 10xxxxxx
            *(stb++)= ((SWAP_BE(stw[0])>>12) & 0xF) | 0xE0; *(stb++)= ((SWAP_BE(stw[0])>>6) & 0x3F) | 0x80; *(stb++)= (SWAP_BE(stw[0]) & 0x3F) | 0x80;
        } 
        
        stw++;
    }
    
    *stb= 0;
}

static void fixpath(char *p)
{
    u8 * pp = (u8 *) p;

    if(*p == '"') {
        p[strlen(p) -1] = 0;
        memcpy(p, p + 1, strlen(p));
    }

    while(*pp) {
        if(*pp == '"') {*pp = 0; break;}
        else
        if(*pp == '\\') *pp = '/';
        else
        if(*pp > 0 && *pp < 32) {*pp = 0; break;}
        pp++;
    }

}

static void get_iso_path(char *path, int indx) 
{
    char aux[0x420];

    path[0] = 0;

    if(!indx) {path[0] = '/'; path[1] = 0; return;}

    while(1) {
        strcpy(aux, directory_iso2[indx].name);
        strcat(aux, path);
        strcpy(path, aux);
       
        indx = directory_iso2[indx].parent - 1;
        if(indx == 0) break;     
    }

}

char *strcpy_malloc(char *STR_DEFAULT)
{
	if(STR_DEFAULT==NULL) return NULL;
	u32 size = strlen(STR_DEFAULT)+1;
	char *STR = malloc(size+1);
	if(STR==NULL) return NULL;
	memset(STR, 0, size+1);
	memcpy(STR, STR_DEFAULT, size);
	return STR;
}

u8 IRD_GetFilesPath(char *ISO_PATH, ird_t *ird)
{
    struct stat s;
    int n;
    
	char path1[0x420];
    char path2[0x420];
    int len_path2 = 0;

	strcpy(path1, ISO_PATH);
    u8 *sectors = NULL;
    u8 *sectors2 = NULL;
    u8 *sectors3 = NULL;

    static char string[0x420];
    static char string2[0x420];
    static u16 wstring[1024];

    struct iso_primary_descriptor sect_descriptor;
    struct iso_directory_record * idr;
    int idx = -1;

	//u32 flba = 0;
	u32 lba;
	u32 p = 0;
	//u32 toc;
	u32 lba0;
	u32 size0;
    
	directory_iso2 = NULL;

    fp_split = NULL;
    fp_split0 = NULL;
    split_index = 0;

    // libc test
    if(sizeof(s.st_size) != 8) {
        printf("Error!: stat st_size must be a 64 bit number!  (size %i)\n\nPress ENTER key to exit\n\n", sizeof(s.st_size));
        return -1;
    }
    
    fixpath(path1);

    n = strlen(path1);

    sprintf(split_file[0].path, "%s", path1);
	
    if(stat(split_file[0].path, &s)<0) {
        printf("Error: ISO file don't exists!\n\nPress ENTER key to exit\n"); return -1;
    }
    split_file[0].size = s.st_size;
    split_file[1].size = 0; // split off


    FILE *fp = fopen(path1, "rb");
    if(!fp) {
        printf("Error!: Cannot open ISO file\n\nPress ENTER key to exit\n\n");
        return -1;
    }

    
    if(fseek(fp, 0x8800, SEEK_SET)<0) {
        printf("Error!: in sect_descriptor fseek\n\n");
        goto err;
    }

    if(fread((void *) &sect_descriptor, 1, 2048, fp) != 2048) {
        printf("Error!: reading sect_descriptor\n\n");
        goto err;
    }

    if(!(sect_descriptor.type[0] == 2 && !strncmp((const char *) &sect_descriptor.id[0], "CD001",5))) {
        printf("Error!: UTF16 descriptor not found\n\nPress ENTER key to exit\n\n");
        goto err;
    }

    //toc = isonum_733(&sect_descriptor.volume_space_size[0]);

    lba0 = isonum_731(&sect_descriptor.type_l_path_table[0]); // lba
    size0 = isonum_733(&sect_descriptor.path_table_size[0]); // tamaño
    //printf("lba0 %u size %u %u\n", lba0, size0, ((size0 + 2047)/2048) * 2048);
    
    if(fseek(fp, lba0 * 2048, SEEK_SET)<0) {
        printf("Error!: in path_table fseek\n\n");
        goto err;
    }

    directory_iso2 = (_directory_iso2 *) malloc((MAX_ISO_PATHS + 1) * sizeof(_directory_iso2));

    if(!directory_iso2) {
        printf("Error!: in directory_is malloc()\n\n");
        goto err;
    }

    memset(directory_iso2, 0, (MAX_ISO_PATHS + 1) * sizeof(_directory_iso2));
 
    sectors = (u8*) malloc(((size0 + 2047)/2048) * 2048);

    if(!sectors) {
        printf("Error!: in sectors malloc()\n\n");
        goto err;
    }

    sectors2 = (u8*) malloc(2048 * 2);

    if(!sectors2) {
        printf("Error!: in sectors2 malloc()\n\n");
        goto err;
    }

    sectors3 = (u8*) malloc(128 * 2048);

    if(!sectors3) {
        printf("Error!: in sectors3 malloc()\n\n");
        goto err;
    }

    if(fread((void *) sectors, 1, size0, fp) != size0) {
        printf("Error!: reading path_table\n\n");
        goto err;
    }

   

    string2[0] = 0;

    fp_split = NULL;
    fp_split0 = NULL;

    split_index = 0;


    idx = 0;

    directory_iso2[idx].name = NULL;

    while(p < size0) {
        u32 snamelen = isonum_721((char *) &sectors[p]);
        if(snamelen == 0) p= ((p/2048) * 2048) + 2048;
        p+=2;
        lba = isonum_731(&sectors[p]);
        p+=4;
        u32 parent =isonum_721((char *) &sectors[p]);
        p+=2;

        memset(wstring, 0, 512 * 2);
        memcpy(wstring, &sectors[p], snamelen);
        
        UTF16_to_UTF8(wstring, (u8 *) string);

        if(idx >= MAX_ISO_PATHS){
            printf("Too much folders (max %i)\n\n", MAX_ISO_PATHS);
            goto err;
        }

        directory_iso2[idx].name = (char *) malloc(strlen(string) + 2);
        if(!directory_iso2[idx].name) {
            printf("Error!: in directory_iso2.name malloc()\n\n");
            goto err;
        }

        strcpy(directory_iso2[idx].name, "/");
        strcat(directory_iso2[idx].name, string);
        
        directory_iso2[idx].parent = parent;
        
        get_iso_path(string2, idx);

        strcat(path2, string2);
		
        path2[len_path2] = 0;
   
        u32 file_lba = 0;
        u64 file_size = 0;

        char file_aux[0x420];

        file_aux[0] = 0;

        int q2 = 0;
        int size_directory = 0;

        while(1) {

            if(fseek(fp, ((u64) lba) * 2048ULL, SEEK_SET)<0) {
                printf("Error!: in directory_record fseek\n\n");
                goto err;
            }

            memset(sectors2 + 2048, 0, 2048);

            if(fread((void *) sectors2, 1, 2048, fp) != 2048) {
                printf("Error!: reading directory_record sector\n\n");
                goto err;
            }

            int q = 0;
            
            if(q2 == 0) {
                idr = (struct iso_directory_record *) &sectors2[q];
                if((int) idr->name_len[0] == 1 && idr->name[0]== 0 && (u64) lba == (u64) (isonum_731((unsigned char *) idr->extent)) && idr->flags[0] == 0x2) {
                    size_directory = isonum_733((unsigned char *) idr->size);
                 
                } else {
                    printf("Error!: Bad first directory record! (LBA %i)\n\n", lba);
                    goto err;
                }
            }

            int signal_idr_correction = 0;

            while(1) {

               
                if(signal_idr_correction) {
                    signal_idr_correction = 0;
                    q-= 2048; // sector correction
                    // copy next sector to first
                    memcpy(sectors2, sectors2 + 2048, 2048);
                    memset(sectors2 + 2048, 0, 2048);
                    lba++;

                    q2 += 2048;

                }

                if(q2 >= size_directory) goto end_dir_rec;
               
                idr = (struct iso_directory_record *) &sectors2[q];

                if(idr->length[0]!=0 && (idr->length[0] + q) > 2048) {

                    printf("Warning! Entry directory break the standard ISO 9660\n\nPress ENTER key\n\n");
                   
                    if(fseek(fp, lba * 2048 + 2048, SEEK_SET)<0) {
                        printf("Error!: in directory_record fseek\n\n");
                        goto err;
                    }

                    if(fread((void *) (sectors2 + 2048), 1, 2048, fp) != 2048) {
                        printf("Error!: reading directory_record sector\n\n");
                        goto err;
                    }

                    signal_idr_correction = 1;

                }

                if(idr->length[0] == 0 && (2048 - q) > 255) goto end_dir_rec;

                if((idr->length[0] == 0 && q != 0) || q == 2048)  { 
                    
                    lba++;
                    q2 += 2048;

                    if(q2 >= size_directory) goto end_dir_rec;

                    if(fseek(fp, (((u64) lba) * 2048ULL), SEEK_SET)<0) {
                        printf("Error!: in directory_record fseek\n\n");
                        goto err;
                    }

                    if(fread((void *) (sectors2), 1, 2048, fp) != 2048) {
                        printf("Error!: reading directory_record sector\n\n");
                        goto err;
                    }
                    memset(sectors2 + 2048, 0, 2048);

                    q = 0;
                    idr = (struct iso_directory_record *) &sectors2[q];

                    if(idr->length[0] == 0 || ((int) idr->name_len[0] == 1 && !idr->name[0])) goto end_dir_rec;
                    
                }

                if((int) idr->name_len[0] > 1 && idr->flags[0] != 0x2 &&
                    idr->name[idr->name_len[0] - 1]== '1' && idr->name[idr->name_len[0] - 3]== ';') { // skip directories
                    
                    memset(wstring, 0, 512 * 2);
                    memcpy(wstring, idr->name, idr->name_len[0]);
                
                    UTF16_to_UTF8(wstring, (u8 *) string); 

                    if(file_aux[0]) {
                        if(strcmp(string, file_aux)) {
    
                            printf("Error!: in batch file %s\n\nPress ENTER key to exit\n\n", file_aux);
                            goto err;
                        }

                        file_size += (u64) (u32) isonum_733(&idr->size[0]);
                        if(idr->flags[0] == 0x80) {// get next batch file
                            q+= idr->length[0]; 
                            continue;
                        } 

                        file_aux[0] = 0; // stop batch file

                    } else {

                        file_lba = isonum_733(&idr->extent[0]);
                        file_size = (u64) (u32) isonum_733(&idr->size[0]);
                        if(idr->flags[0] == 0x80) {
                            strcpy(file_aux, string);
                            q+= idr->length[0];
                            continue;  // get next batch file
                        }
                    }

                    int len = strlen(string);

                    string[len - 2] = 0; // break ";1" string
                    
                    len = strlen(string2);
					if(strcmp(string2, "/") != 0)	strcat(string2, "/");
                    strcat(string2, string);
                    
                    int i;
                    for(i=0; i<ird->FileHashesNumber; i++) {
                        if( ird->FileHashes[i].Sector == file_lba) {
                            ird->FileHashes[i].FilePath = strcpy_malloc(string2);
                            if(ird->FileHashes[i].FilePath==NULL) {printf("ird->FileHashes[i].FilePath malloc failed");}
                            ird->FileHashes[i].FileSize = file_size;
                            break;
                        }
					}
                    
                    path2[len_path2] = 0;
                    string2[len] = 0;
					
                }

                q+= idr->length[0];
            }

            lba ++; 
            q2+= 2048;
            if(q2 >= size_directory) goto end_dir_rec;

        }

        end_dir_rec:

        p+= snamelen;
        if(snamelen & 1) p++;

        idx++;

    }

    if(fp) fclose(fp);
    if(split_index && fp_split) {fclose(fp_split); fp_split = NULL;}
    if(sectors) free(sectors);
    if(sectors2) free(sectors2);
    if(sectors3) free(sectors3);

    for(n = 0; n <= idx; n++)
        if(directory_iso2[n].name) {free(directory_iso2[n].name); directory_iso2[n].name = NULL;}
    
    if(directory_iso2) free(directory_iso2); 

    return 0;

err:

    if(fp) fclose(fp);
    if(split_index && fp_split) {fclose(fp_split); fp_split = NULL;}

    if(sectors) free(sectors);
    if(sectors2) free(sectors2);
    if(sectors3) free(sectors3);

    for(n = 0; n <= idx; n++)
        if(directory_iso2[n].name) {free(directory_iso2[n].name); directory_iso2[n].name = NULL;}
    
    if(directory_iso2) free(directory_iso2);

    return -1;
}

u8 IRD_GetRegionBoundaries(char *ISO_PATH, ird_t *ird)
{
    FILE *f = fopen(ISO_PATH, "rb");
    if(f==NULL) {
        print_load("Error: IRD_GetRegionBoundaries fopen failed");
        return FAILED;
    }

    u32 RegionNumber;
   
    fread(&RegionNumber, sizeof(u32), 1, f);
    RegionNumber = SWAP_BE(RegionNumber);
    
    if( RegionNumber*2-1 != ird->RegionHashesNumber ) {
        printf("Error : Region numbers are different, (header) %X != %X (IRD)\n", RegionNumber, ird->RegionHashesNumber);
        FCLOSE(f);
        return FAILED;
    }
    
    fseek(f, 8, SEEK_SET);
    
    
    int i;
    for(i=0; i<ird->RegionHashesNumber; i+=2){
        
        fread(&ird->RegionHashes[i].Start, sizeof(u32), 1, f);
        ird->RegionHashes[i].Start = SWAP_BE(ird->RegionHashes[i].Start);
        if( i!= 0 ){
            ird->RegionHashes[i-1].End = ird->RegionHashes[i].Start - 1;
        }
        
        fread(&ird->RegionHashes[i].End, sizeof(u32), 1, f);
        ird->RegionHashes[i].End = SWAP_BE(ird->RegionHashes[i].End);
        
        if( i + 1 < ird->RegionHashesNumber) {
            ird->RegionHashes[i+1].Start = ird->RegionHashes[i].End + 1;
        }
    }
    
    
    FCLOSE(f);
    
    return SUCCESS;
}

u8 GetPVD(char *ISO, u8 *PVD)
{
    memset(PVD, 0, 0x60);
    
    FILE *f = fopen(ISO, "rb");
    if(f==NULL) return FAILED;
    
    fseek(f, 0x8320, SEEK_SET);
    fread(PVD, 0x60, 1, f);
    fclose(f);
    
    return SUCCESS;
}