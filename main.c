#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#if defined (__MSVCRT__)
#undef __STRICT_ANSI__ // ugly
#include <string.h>
#define strcasecmp	_strcmpi
#define stat _stati64
#else
#include <string.h>
#endif

#include "aes.h"

#include "ird_build.h"
#include "ird_iso.h"
#include "md5.h"

#ifdef _WIN32
	#define mkdir(path, mode) mkdir(path)
#endif

#define TITLE "ird_tools v0.4\n\n"

u8 verbose=0;
u8 get_data;

u32 IRD_extra_sig(ird_t *ird);
u32 IRD_keys_sig(ird_t *ird);
u32 IRD_files_sig(ird_t *ird);
u32 IRD_meta_sig(ird_t *ird);
void dec_d2(unsigned char* d2);
void dec_d1(unsigned char* d1);
void enc_d2(unsigned char* d2);
void enc_d1(unsigned char* d1);

void fputs_hex(u8 *data, size_t len, FILE *f)
{
   int i = 0;
   char line[33];
   memset(line, 0, 33);
   
   while( i < len) {
       
        sprintf(&line[i%16*2], "%02X",  data[i]);
        if((i>0 && i%16 == 15) || i == (len-1)) {
            fputs(line, f);
            memset(line, 0, 33);
        }
        i++;
   } 
}

char *GetExtension(char *path)
{
    int n = strlen(path);
    int m = n;

    while(m > 1 && path[m] != '.' && path[m] != '/') m--;
    
	
    if(strcmp(&path[m], ".0")==0 || strcmp(&path[m], ".66600")==0) { // splitted
       m--;
       while(m > 1 && path[m] != '.' && path[m] != '/') m--; 
    }
	
	if(strcasecmp(&path[m], ".bin")==0) {
		if(strcasecmp(&path[m-7], ".header.bin")==0) {
			m-=7;	
		}
	}
  
    if(path[m] == '.') return &path[m];

    return &path[n];
}

void IRD_extract(char *IRD_PATH)
{	
	int ret, i;

	ird_t *ird=IRD_load(IRD_PATH);
	if(ird==NULL) return;
	
	char msg[512];
	char IRD_LOG[512];
	char IRD_HEADER[512];
	char IRD_FOOTER[512];
	char IRD_DISC_KEY[512];
	char IRD_JSON[512];
	char TEMP[512];
	
	strcpy(TEMP, IRD_PATH);
	
	TEMP[strlen(IRD_PATH)-4] = 0; 
	
	sprintf(IRD_JSON, "%s.json"        , TEMP);
	sprintf(IRD_LOG, "%s.log.txt"      , TEMP);
	sprintf(IRD_HEADER, "%s.header.bin", TEMP);
	sprintf(IRD_FOOTER, "%s.footer.bin", TEMP);
	sprintf(IRD_DISC_KEY, "%s.disc.key", TEMP);
	
	print_verbose("GZ_decompress7 header %X", ird->HeaderLength);
	ret = GZ_decompress7((char *) ird->Header, ird->HeaderLength, IRD_HEADER);
	if( ret != Z_OK ) {
		printf("Error : failed to decompress header (%s)", ret);
		FREE_IRD(ird);
		return;
	}
	
	if( get_data & GET_FOOTER ) {
		print_verbose("GZ_decompress7 footer");
		ret = GZ_decompress7((char *) ird->Footer, ird->FooterLength, IRD_FOOTER);
		if( ret != Z_OK ) {
			printf("Error : failed to decompress footer (%s)", ret);
			FREE_IRD(ird);
			return;
		}
	}
	
	print_verbose("IRD_GetFilesPath");
	IRD_GetFilesPath(IRD_HEADER, ird);
	
	print_verbose("IRD_GetRegionBoundaries");
	if( IRD_GetRegionBoundaries(IRD_HEADER, ird) == FAILED ) {
		print_load("Error: failed to IRD_GetRegionBoundaries %s", IRD_PATH);
		return;
	}
	
	/*
	print_verbose("disc.key");
	FILE *dk;
	dk = fopen(IRD_DISC_KEY, "wb");
	if(dk==NULL) {
		printf("Error : failed to create disc.key");
		FREE_IRD(ird);
		return;
	}
	fputs("Encrypted 3K RIP", dk);
	fwrite(&ird->Data1, 1, 0x10, dk);
	fwrite(&ird->Data2, 1, 0x10, dk);
	fwrite(&ird->PIC, 1, 0x73, dk);
	fclose(dk);
	*/
	
	FILE *log=NULL;
	log=fopen(IRD_LOG, "w");
	if(log==NULL) {
		printf("Error : failed to open %s", IRD_LOG);
		FREE_IRD(ird);
		return;
	}
	
	FILE *json=fopen(IRD_JSON, "w");
	if(json==NULL) {
		printf("Error : failed to open %s", IRD_JSON);
		fclose(log);
		FREE_IRD(ird);
		return;
	}
	
	u32 meta_sig = IRD_meta_sig(ird);
	u32 files_sig = IRD_files_sig(ird);
	u32 extra_sig = IRD_extra_sig(ird);
	u32 keys_sig = IRD_keys_sig(ird);
	if( !meta_sig || !files_sig || !extra_sig || !keys_sig) {
		FREE_IRD(ird);
		fclose(log);
		return;
	}
	
	  fputs("{\n", json);

	// maybe used for ird portal
	// trust_level = UPLOADERS_ID.count 
	  fputs(     "\t\"TRUST_LVL\" : 0,\n", json);
	  fputs(     "\t\"UPLOADERS\" : [],\n", json);
	  fputs(     "\t\"UPLOADERS_ID\" : [],\n", json);
	  
	sprintf(msg, "\t\"MGZ_SIG\" : \"%08X_%08X_%08X_%08X\",\n", meta_sig, files_sig, extra_sig, keys_sig);fputs(msg, json);
	unsigned char ird_md5[16];
	md5_file((const char *) IRD_PATH, ird_md5);
	sprintf(msg, "\t\"MD5\" : \"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\",\n", 
						ird_md5[0x0],
						ird_md5[0x1],
						ird_md5[0x2],
						ird_md5[0x3],
						ird_md5[0x4],
						ird_md5[0x5],
						ird_md5[0x6],
						ird_md5[0x7],
						ird_md5[0x8],
						ird_md5[0x9],
						ird_md5[0xA],
						ird_md5[0xB],
						ird_md5[0xC],
						ird_md5[0xD],
						ird_md5[0xE],
						ird_md5[0xF]); fputs(msg, json);
	 
	 
	
	
	// Values from IRD
	sprintf(msg, "\t\"TITLE\" : \"%s\",\n", ird->GameName);fputs(msg, json);
	sprintf(msg, "\t\"TITLE_ID\" : \"%s\",\n", ird->GameId);fputs(msg, json);
	sprintf(msg, "\t\"GAME_VER\" : \"%s\",\n", ird->GameVersion);fputs(msg, json);
	sprintf(msg, "\t\"SYS_VER\" : \"%s\",\n", ird->UpdateVersion);fputs(msg, json);
	sprintf(msg, "\t\"APP_VER\" : \"%s\",\n", ird->AppVersion);fputs(msg, json);
	
	sprintf(msg, "\t\"HEADER_LEN\" : %d,\n", ird->HeaderLength);fputs(msg, json);
	sprintf(msg, "\t\"FOOTER_LEN\" : %d,\n", ird->FooterLength);fputs(msg, json);
	sprintf(msg, "\t\"DISC_SIZE\" : %lld,\n", (u64) ((u64) ird->RegionHashes[ird->RegionHashesNumber-1].End * 0x800ULL));fputs(msg, json);
	sprintf(msg, "\t\"IRD_VERSION\" : %d,\n", ird->Version);fputs(msg, json);
	sprintf(msg, "\t\"EXTRA_CONFIG\" : \"%X\",\n", ird->ExtraConfig);fputs(msg, json);
	sprintf(msg, "\t\"ATTACHMENTS\" : \"%X\",\n", ird->Attachments);fputs(msg, json);
	sprintf(msg, "\t\"UNIQUE_ID\" : \"%08X\",\n", ird->UniqueIdentifier);fputs(msg, json);
	sprintf(msg, "\t\"CRC\" : \"%08X\",\n", ird->crc);fputs(msg, json);
	
	  fputs(     "\t\"FILES\" :\n", json);
	  fputs(     "\t[\n", json);
	
	sprintf(msg, "Game Name : %s\nGame ID : %s\nUpdate : %s\nGame Version : %s\nApp Version : %s\n", ird->GameName, ird->GameId, ird->UpdateVersion, ird->GameVersion, ird->AppVersion);
	fputs(msg, log);
	sprintf(msg, "Files Number = %d\n", ird->FileHashesNumber);
	fputs(msg, log);
	
	fputs("_______________________________________________________________ _ _ _\n", log);
	fputs("                                  |                 |\n", log);
	fputs(" MD5                              | SECTOR          | PATH\n", log);
	fputs("__________________________________|_________________|__________ _ _ _\n", log);
	fputs("                                  |                 |\n", log);
	u8 current_region=0;
	u8 plain = 1;
	for(i=0; i<ird->FileHashesNumber; i++) {
		  fputs(     "\t\t{\n", json);
		sprintf(msg, "\t\t\t\"PATH\" : \"%s\",\n", ird->FileHashes[i].FilePath);fputs(msg, json);
		sprintf(msg, "\t\t\t\"MD5\" : \"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\",\n", 
						ird->FileHashes[i].FileHash[0x0],
						ird->FileHashes[i].FileHash[0x1],
						ird->FileHashes[i].FileHash[0x2],
						ird->FileHashes[i].FileHash[0x3],
						ird->FileHashes[i].FileHash[0x4],
						ird->FileHashes[i].FileHash[0x5],
						ird->FileHashes[i].FileHash[0x6],
						ird->FileHashes[i].FileHash[0x7],
						ird->FileHashes[i].FileHash[0x8],
						ird->FileHashes[i].FileHash[0x9],
						ird->FileHashes[i].FileHash[0xA],
						ird->FileHashes[i].FileHash[0xB],
						ird->FileHashes[i].FileHash[0xC],
						ird->FileHashes[i].FileHash[0xD],
						ird->FileHashes[i].FileHash[0xE],
						ird->FileHashes[i].FileHash[0xF]);fputs(msg, json);
		sprintf(msg, "\t\t\t\"SECTOR\" : %d,\n", ird->FileHashes[i].Sector);fputs(msg, json);
		sprintf(msg, "\t\t\t\"SIZE\" : %d,\n", ird->FileHashes[i].FileSize);fputs(msg, json);
		if( ird->RegionHashes[current_region].End < ird->FileHashes[i].Sector ) {
			plain = !plain;
			current_region+=1;
		}
		if( plain ) {
			fputs("\t\t\t\"TYPE\" : \"Plain\"\n", json);
		} else {
			fputs("\t\t\t\"TYPE\" : \"Encrypted\"\n", json);
		}
		
		sprintf(msg, " %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X | %-15d | ", 
						ird->FileHashes[i].FileHash[0x0],
						ird->FileHashes[i].FileHash[0x1],
						ird->FileHashes[i].FileHash[0x2],
						ird->FileHashes[i].FileHash[0x3],
						ird->FileHashes[i].FileHash[0x4],
						ird->FileHashes[i].FileHash[0x5],
						ird->FileHashes[i].FileHash[0x6],
						ird->FileHashes[i].FileHash[0x7],
						ird->FileHashes[i].FileHash[0x8],
						ird->FileHashes[i].FileHash[0x9],
						ird->FileHashes[i].FileHash[0xA],
						ird->FileHashes[i].FileHash[0xB],
						ird->FileHashes[i].FileHash[0xC],
						ird->FileHashes[i].FileHash[0xD],
						ird->FileHashes[i].FileHash[0xE],
						ird->FileHashes[i].FileHash[0xF],
						ird->FileHashes[i].Sector);
		fputs(msg, log);
		sprintf(msg, "%s\n", ird->FileHashes[i].FilePath);
		fputs(msg, log);
		 
		 if( i < ird->FileHashesNumber - 1 ) {
		  	 fputs("\t\t},\n", json);
		 } else {
		 	 fputs("\t\t}\n", json);
		 }
	}
	fputs("__________________________________|_________________|__________ _ _ _\n\n", log);

	fputs("\t],\n", json);
	fputs("\t\"REGION\" :\n", json);
	fputs("\t[\n", json);
	
	sprintf(msg, "Region Number = %d\n", ird->RegionHashesNumber);
	fputs(msg, log);
	fputs("_________________________________________________________\n", log);
	fputs("                                  |                      |\n", log);
	fputs("  MD5                             | REGION               |\n", log);
	fputs("__________________________________|______________________|\n", log);
	fputs("                                  |                      |\n", log);
	plain=1;
	for(i=0; i<ird->RegionHashesNumber; i++) {
		fputs(       "\t\t{\n", json);
		sprintf(msg, "\t\t\t\"MD5\": \"%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\",\n", 
						ird->RegionHashes[i].RegionHash[0x0],
						ird->RegionHashes[i].RegionHash[0x1],
						ird->RegionHashes[i].RegionHash[0x2],
						ird->RegionHashes[i].RegionHash[0x3],
						ird->RegionHashes[i].RegionHash[0x4],
						ird->RegionHashes[i].RegionHash[0x5],
						ird->RegionHashes[i].RegionHash[0x6],
						ird->RegionHashes[i].RegionHash[0x7],
						ird->RegionHashes[i].RegionHash[0x8],
						ird->RegionHashes[i].RegionHash[0x9],
						ird->RegionHashes[i].RegionHash[0xA],
						ird->RegionHashes[i].RegionHash[0xB],
						ird->RegionHashes[i].RegionHash[0xC],
						ird->RegionHashes[i].RegionHash[0xD],
						ird->RegionHashes[i].RegionHash[0xE],
						ird->RegionHashes[i].RegionHash[0xF]); fputs(msg, json);
						
		sprintf(msg, "\t\t\t\"START\": %d,\n",	ird->RegionHashes[i].Start); fputs(msg, json);
		sprintf(msg, "\t\t\t\"END\": %d,\n",	ird->RegionHashes[i].End); fputs(msg, json);
		if( plain ) {
			fputs("\t\t\t\"TYPE\" : \"Plain\",\n", json);
		} else {
			fputs("\t\t\t\"TYPE\" : \"Encrypted\",\n", json);
		}
		
		sprintf(msg, " %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X | %-20d |\n", 
						ird->RegionHashes[i].RegionHash[0x0],
						ird->RegionHashes[i].RegionHash[0x1],
						ird->RegionHashes[i].RegionHash[0x2],
						ird->RegionHashes[i].RegionHash[0x3],
						ird->RegionHashes[i].RegionHash[0x4],
						ird->RegionHashes[i].RegionHash[0x5],
						ird->RegionHashes[i].RegionHash[0x6],
						ird->RegionHashes[i].RegionHash[0x7],
						ird->RegionHashes[i].RegionHash[0x8],
						ird->RegionHashes[i].RegionHash[0x9],
						ird->RegionHashes[i].RegionHash[0xA],
						ird->RegionHashes[i].RegionHash[0xB],
						ird->RegionHashes[i].RegionHash[0xC],
						ird->RegionHashes[i].RegionHash[0xD],
						ird->RegionHashes[i].RegionHash[0xE],
						ird->RegionHashes[i].RegionHash[0xF], i+1);
		fputs(msg, log);
		plain = !plain;
		if( i < ird->RegionHashesNumber - 1 ) {
			fputs("\t\t},\n", json);
		} else {
			fputs("\t\t}\n", json);
		}	
	}
	fputs("__________________________________|______________________|\n\n", log);
	
	fputs("Data1 = ", log); fputs_hex(ird->Data1     , 0x10, log); fputs("\n", log);
	fputs("Data2 = ", log); fputs_hex(ird->Data2     , 0x10, log); fputs("\n", log);
	fputs("PIC   = ", log); fputs_hex(ird->PIC + 0x00, 0x10, log); fputs("\n", log);
	fputs("        ", log); fputs_hex(ird->PIC + 0x10, 0x10, log); fputs("\n", log);
	fputs("        ", log); fputs_hex(ird->PIC + 0x20, 0x10, log); fputs("\n", log);
	fputs("        ", log); fputs_hex(ird->PIC + 0x30, 0x10, log); fputs("\n", log);
	fputs("        ", log); fputs_hex(ird->PIC + 0x40, 0x10, log); fputs("\n", log);
	fputs("        ", log); fputs_hex(ird->PIC + 0x50, 0x10, log); fputs("\n", log);
	fputs("        ", log); fputs_hex(ird->PIC + 0x60, 0x10, log); fputs("\n", log);
	fputs("        ", log); fputs_hex(ird->PIC + 0x70, 0x03, log); fputs("\n\n", log);
	
	
	sprintf(msg, "MGZ_SIG = %08X_%08X_%08X_%08X\n", meta_sig, files_sig, extra_sig, keys_sig);
	fputs(msg, log);
	fclose(log);
	
		
	fputs("\t],\n", json);
	fputs("\t\"DATA1_DEC\" : \"", json); fputs_hex(ird->Data1     , 0x10, json); fputs("\",\n", json);
	enc_d1(ird->Data1);
	fputs("\t\"DATA1_ENC\" : \"", json); fputs_hex(ird->Data1     , 0x10, json); fputs("\",\n", json);
	dec_d2(ird->Data2);
	fputs("\t\"DATA2_DEC\" : \"", json); fputs_hex(ird->Data2     , 0x10, json); fputs("\",\n", json);
	enc_d2(ird->Data2);
	fputs("\t\"DATA2_ENC\" : \"", json); fputs_hex(ird->Data2     , 0x10, json); fputs("\",\n", json);	
	
	fputs("\t\"PIC\" : \"", json); fputs_hex(ird->PIC     , 0x73, json); fputs("\",\n", json);
	
	print_verbose("GetPVD");
	u8 PVD[0x60] = {0};
	if( GetPVD(IRD_HEADER, PVD) == SUCCESS ) {
		fputs("\t\"PVD\" : \"", json); fputs_hex(PVD, 0x60, json); fputs("\"\n", json);
	} else {
		print_load("Error: failed to getPVD");
	}
	
	fputs("}\n", json);
	
	fclose(json);
	FREE_IRD(ird);
	
	if(! (get_data & GET_JSON) ) {
		remove(IRD_JSON);
	}
	if(! (get_data & GET_HEADER) ) {
		remove(IRD_HEADER);
	}
	if(! (get_data & GET_TXT) ) {
		remove(IRD_LOG);
	}
}

#define BUFFER_SIZE		0x100000
u32 crc_file2(char *path, u32 current_crc)
{
	FILE *f;
    u32 crc=current_crc;
    u64 file_size;
	u64 read=0;
	u64 n;
	
	u8 *buf = (u8 *) malloc(BUFFER_SIZE);
	if(buf == NULL) {
		return 0;
	}
	
	f = fopen( path, "rb");
    if( f == NULL ) {
		FREE(buf);
		return 0;
	}
	
	fseek (f , 0 , SEEK_END);
	file_size = (u64) ftell (f);
	fseek(f, 0, SEEK_SET);
	
	while(read < file_size) {
		if( read + BUFFER_SIZE > file_size) n = file_size-read;
		else n = BUFFER_SIZE;
		
		fread(buf, sizeof(u8), n, f);
		read += n;
		
		crc = crc32(crc, (const unsigned char*) buf, n);
	}
	FREE(buf);
    FCLOSE(f);
	
    return crc;
}

u32 crc_file(char *path)
{
	u32 crc = crc32(0L, Z_NULL, 0);
	crc = crc_file2(path, crc);
    return crc;
}

u32 IRD_keys_sig(ird_t *ird)
{
	u32 crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc,  (const unsigned char*) ird->Data1 , 0x10);
	crc = crc32(crc,  (const unsigned char*) ird->PIC   , 0x73);
	return crc;
}

u32 IRD_extra_sig(ird_t *ird)
{
	char TempDir[512];
	char header_path[512];
	char footer_path[512];
	
	sprintf(TempDir, "temp");
	mkdir(TempDir, 0777);
	sprintf(header_path, "%s/%s.header.bin", TempDir, ird->GameId);
	unlink(header_path);
	sprintf(footer_path, "%s/%s.footer.bin", TempDir, ird->GameId);
	unlink(footer_path);
	u32 crc = crc32(0L, Z_NULL, 0);
	int ret = GZ_decompress7( (char *) ird->Header, ird->HeaderLength, header_path);
	if( ret != Z_OK) {
		print_load("Error : IRD_extra_sig failed to extract (%d) : %s", ret, header_path);
		goto error;
	}
	ret = GZ_decompress7( (char *) ird->Footer, ird->FooterLength, footer_path);
	if( ret != Z_OK) {
		print_load("Error : IRD_extra_sig failed to extract (%d) : %s", ret, footer_path);
		goto error;
	}
	crc = crc_file2(header_path, crc);
	if( crc == 0 ) {
		print_load("Error : IRD_extra_sig failed to get crc of %s", ret, header_path);
		goto error;
	}
	crc = crc_file2(footer_path, crc);
	if( crc == 0 ) {
		print_load("Error : IRD_extra_sig failed to get crc of %s", ret, footer_path);
		goto error;
	}
	
error :
	unlink(header_path);
	unlink(footer_path);
	
	return crc;
}

u32 IRD_files_sig(ird_t *ird)
{
	u32 crc = crc32(0L, Z_NULL, 0);
	
	int i;
	for(i=0; i<ird->FileHashesNumber; i++) {	
		u64 sect = ENDIAN_SWAP_64(ird->FileHashes[i].Sector);
		crc = crc32(crc,  (const unsigned char*) &sect					     , 0x8);
		crc = crc32(crc,  (const unsigned char*) ird->FileHashes[i].FileHash , 0x10);
	}
	
	return crc;
}

u32 IRD_meta_sig(ird_t *ird)
{
	u32 crc = crc32(0L, Z_NULL, 0);
	
	crc = crc32(crc,  (const unsigned char*) ird->GameId                , 9);
	crc = crc32(crc,  (const unsigned char*) ird->UpdateVersion         , 4);
	crc = crc32(crc,  (const unsigned char*) ird->GameVersion           , 5);
	crc = crc32(crc,  (const unsigned char*) ird->AppVersion            , 5);
	
	return crc;
}

void IRD_rename(char *IRD_PATH)
{
	char NEW_PATH[512];
	char NEW_NAME[512];
	char IRDU_PATH[512];
	
	sprintf(IRDU_PATH, "%su", IRD_PATH);
	
	ird_t *ird=IRD_load(IRD_PATH);
	unlink(IRDU_PATH);
	if(ird==NULL) {
		printf("ird==NULL");
		return;
	}
	
	u32 meta_sig = IRD_meta_sig(ird);
	u32 files_sig = IRD_files_sig(ird);
	u32 extra_sig = IRD_extra_sig(ird);
	u32 keys_sig = IRD_keys_sig(ird);
	if( !meta_sig || !files_sig || !extra_sig || !keys_sig) {
		FREE_IRD(ird);
		return;
	}
	
	memset(NEW_NAME, 0, 512);
	memset(NEW_PATH, 0, 512);
	
	sprintf(NEW_NAME, "%08X_%08X_%08X_%08X.ird\0", meta_sig, files_sig, extra_sig, keys_sig);
	
	if(strstr(IRD_PATH, "/")!=NULL){
		strcpy(NEW_PATH, IRD_PATH);
		int l =  strlen(NEW_PATH);
		while(l>0){
			l--;
			if(NEW_PATH[l]=='/') break;
			NEW_PATH[l]=0;
		}
		strcpy(NEW_PATH+l+1, NEW_NAME);
	} else {
		strcpy(NEW_PATH, NEW_NAME);
	}

	rename(IRD_PATH, NEW_PATH);
}

/*
 It check if someone generated an corrupted ird with a wrong size of header 
 Issue from managunz : https://github.com/Zarh/ManaGunZ/issues/58#
*/
void check_header_size(char *IRD_PATH)
{	
	FILE *f = fopen("check_header.txt", "a");
	if( f == NULL) return;
	
	u8 del_h=0;
	u8 del_u=0;
	
	char HEADER_PATH[512]={0};
	char IRDU_PATH[512]={0};
	int len = strlen(IRD_PATH);
	IRD_PATH[len-4] = 0;
	sprintf(HEADER_PATH, "%s.header.bin", IRD_PATH);
	IRD_PATH[len-4] = '.';
	sprintf(IRDU_PATH, "%su", IRD_PATH);
	
	struct stat s;
	if( stat(IRDU_PATH, &s) != 0) del_u=1;
	
	ird_t *ird=IRD_load(IRD_PATH);
	if(ird==NULL) return;
	
    if( stat(HEADER_PATH, &s) != 0) {
		int ret = GZ_decompress7( (char *) ird->Header, ird->HeaderLength, HEADER_PATH);
		if( ret != Z_OK) {
			print_load("Error : check_header_size failed to extract (%d) : %s", ret, HEADER_PATH);
			return;
		}
		stat(HEADER_PATH, &s);
		del_h=1;
	}
	
	char str[512]={0};
	sprintf(str, "%s = ", IRD_PATH);
	if( ird->FileHashes[0].Sector * 0x800 == s.st_size){
		strcat(str, "OK\n");
	} else {
		strcat(str, "ERROR\n");
	}
	fputs(str, f);
	fclose(f);

	FREE_IRD(ird);
	
	if(del_h) remove(HEADER_PATH);
	if(del_h) remove(IRDU_PATH);
}

u8 is_dir(char *path)
{
	struct stat path_stat;
    stat(path, &path_stat);
    return S_ISDIR(path_stat.st_mode);
}

void print_help()
{
	printf(TITLE);
	
		printf( "Usage:\n"
				"  Format:\n"
				"    ird_tools [options] <input>\n"
				"  Description :\n"
				"    Manage ISO Rebuild Data files (IRD).\n"
				"  Options:\n"
				"    -e, --extract (DEFAULT)         Extract data from IRD.\n"
				"      -x, --header                  Extract header from IRD\n"
				"      -f, --footer                  Extract footer from IRD\n"
				"      -j, --json                    Extract informations from IRD to a json\n"
				"      -t, --txt                     Extract informations from IRD to a txt file\n"
				"      -u, --uncompressed            Extract uncompressed IRD file.\n"
				"      -a, --all (DEFAULT)           Extract everything quoted above.\n"
				"    -r, --rename                    Rename IRD with MGZ_SIG.\n"
				"    -i, --integrity                 Check integrity of IRD.\n"
				"    -h, --help                      This help text.\n"
				"    -v, --verbose                   Make the operation more talkative.\n"
				"  Arguments:\n"
				"    <input>                         Path of IRD.\n"
				"  Note:\n"
				"    It supports multiple inputs as files or directories.\n"
				"    For example: ird_tools [ird_path1] [ird_path2] ...\n"
				"    Directories are scanned recursively.\n"
				);
}

#define do_extract			 	0
#define do_rename				1
#define do_integrity	2

void do_it(char *path, u8 task)
{
	switch(task)
	{
		case do_extract:
		{
			IRD_extract(path);
		}
		break;
		case do_rename:
		{
			IRD_rename(path);
		}
		break;
		case do_integrity:
		{
			check_header_size(path);
			// todo check if TITLE is "Additionnal Content" (PKGDIR issue)
			//check_additionnal_content(path);
		}
		break;
		default:
		{
			print_help();
		}
		break;
	}
}

void do_task(char *path_in, u8 task)
{
	DIR *d;
	struct dirent *dir;
	
	char path[512];
	strcpy(path, path_in);
	int l = strlen(path);
	int i;
	
	for(i=0;i<l;i++){
		if(path[i]=='\\') path[i]='/';
	}
	
	if( is_dir(path) ) {
		d = opendir(path);
		if(d==NULL) return;
		
		while ((dir = readdir(d))) {
			if(!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) continue;		
			
			char temp[512];
			sprintf(temp, "%s/%s", path, dir->d_name);
			
			if(is_dir(temp)) do_task(temp, task);
			else {
				
				char *ext = GetExtension(temp);
				if( strcasecmp(ext, ".ird") == 0) {
					do_it(temp, task);
				}
			}
		}
		closedir(d);
	} else {
		char *ext = GetExtension(path);
		if( strcasecmp(ext, ".ird") == 0) {
			do_it(path, task);
		}
	}
}

int main (int argc, char **argv)
{	
	if(argc==1) print_help();
	
	u8 task = do_extract;
	verbose=0;
	get_data=0;
	
	u32 a = 1;
    int i;
    for(i=1; i<argc; i++) {
        if( !strcmp(argv[i], "-e") || !strcmp(argv[i], "--extract") ) {
            task = do_extract;
            a++;
        } else 
        if( !strcmp(argv[i], "-r") || !strcmp(argv[i], "--rename") ) {
            task = do_rename;
            a++;
        } else 
        if( !strcmp(argv[i], "-i") || !strcmp(argv[i], "--integrity") ) {
            task = do_integrity;
            a++;
        } else 
        if( !strcmp(argv[i], "-x") || !strcmp(argv[i], "--header") ) {
            if(! (get_data & GET_HEADER) ) get_data |= GET_HEADER;
            a++;
        } else 
        if( !strcmp(argv[i], "-f") || !strcmp(argv[i], "--footer") ) {
            if(! (get_data & GET_FOOTER) ) get_data |= GET_FOOTER;
            a++;
        } else 
		if( !strcmp(argv[i], "-j") || !strcmp(argv[i], "--json") ) {
            if(! (get_data & GET_JSON) ) get_data |= GET_JSON;
            a++;
        } else 
		if( !strcmp(argv[i], "-t") || !strcmp(argv[i], "--txt") ) {
            if(! (get_data & GET_TXT) ) get_data |= GET_TXT;
            a++;
        } else 
		if( !strcmp(argv[i], "-u") || !strcmp(argv[i], "--uncompressed") ) {
            if(! (get_data & GET_IRDU) ) get_data |= GET_IRDU;
            a++;
        } else
		if( !strcmp(argv[i], "-a") || !strcmp(argv[i], "--all") ) {
            get_data = GET_ALL;
            a++;
        } else
        if( !strcmp(argv[i], "-v") ||  !strcmp(argv[i], "--verbose") ) {
            verbose=1;
            a++;
        } else
        if( !strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_help();
            return 0;
        }
    }
 	
	if(get_data == 0) get_data=GET_ALL;
	
	for(i=a;i<argc;i++) {
		do_task(argv[i], task);
	}
	
	rmdir("temp");
	
	return 0;
}

// Crypto functions (AES128-CBC, AES128-ECB, SHA1-HMAC and AES-CMAC).
void aes_cbc_decrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len)
{
	aes_context ctx;
	aes_setkey_dec(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_DECRYPT, len, iv, in, out);

	// Reset the IV.
	memset(iv, 0, 0x10);
}

void aes_cbc_encrypt(unsigned char *key, unsigned char *iv, unsigned char *in, unsigned char *out, int len)
{
	aes_context ctx;
	aes_setkey_enc(&ctx, key, 128);
	aes_crypt_cbc(&ctx, AES_ENCRYPT, len, iv, in, out);

	// Reset the IV.
	memset(iv, 0, 0x10);
}

void dec_d1(unsigned char* d1)
{
	unsigned char key[]= { 0x38, 11, 0xcf, 11, 0x53, 0x45, 0x5b, 60, 120, 0x17, 0xab, 0x4f, 0xa3, 0xba, 0x90, 0xed };
	unsigned char iV[] = { 0x69, 0x47, 0x47, 0x72, 0xaf, 0x6f, 0xda, 0xb3, 0x42, 0x74, 0x3a, 0xef, 170, 0x18, 0x62, 0x87 };
	
	aes_cbc_decrypt(key, iV, d1, d1, 16);
}

void dec_d2(unsigned char* d2)
{
	unsigned char key[]= { 0x7c, 0xdd, 14, 2, 7, 110, 0xfe, 0x45, 0x99, 0xb1, 0xb8, 0x2c, 0x35, 0x99, 0x19, 0xb3 };
	unsigned char iV[] = { 0x22, 0x26, 0x92, 0x8d, 0x44, 3, 0x2f, 0x43, 0x6a, 0xfd, 0x26, 0x7e, 0x74, 0x8b, 0x23, 0x93 };
	aes_cbc_decrypt(key, iV, d2, d2, 16);
}

void enc_d1(unsigned char* d1)
{
	unsigned char key[]= { 0x38, 11, 0xcf, 11, 0x53, 0x45, 0x5b, 60, 120, 0x17, 0xab, 0x4f, 0xa3, 0xba, 0x90, 0xed };
	unsigned char iV[] = { 0x69, 0x47, 0x47, 0x72, 0xaf, 0x6f, 0xda, 0xb3, 0x42, 0x74, 0x3a, 0xef, 170, 0x18, 0x62, 0x87 };
	aes_cbc_encrypt(key, iV, d1, d1, 16);
}

void enc_d2(unsigned char* d2)
{
	unsigned char key[]= { 0x7c, 0xdd, 14, 2, 7, 110, 0xfe, 0x45, 0x99, 0xb1, 0xb8, 0x2c, 0x35, 0x99, 0x19, 0xb3 };
	unsigned char iV[] = { 0x22, 0x26, 0x92, 0x8d, 0x44, 3, 0x2f, 0x43, 0x6a, 0xfd, 0x26, 0x7e, 0x74, 0x8b, 0x23, 0x93 };
	aes_cbc_encrypt(key, iV, d2, d2, 16);
}