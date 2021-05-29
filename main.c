#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

#include "ird_build.h"
#include "ird_iso.h"
#include "md5.h"

u32 IRD_extra_sig(ird_t *ird);
u32 IRD_keys_sig(ird_t *ird);
u32 IRD_files_sig(ird_t *ird);
u32 IRD_meta_sig(ird_t *ird);

void print_help()
{
	printf(
"ird_tools.exe version 0.2\n\n\
To extract informations from the ird\n\
	ird_tools.exe [ird_path1] [ird_path2] ...\n\
  	Drag&Drop the ird(s) on the exe\n\n\
To rename the ird with its signature '[TITLE_ID]_[SIGNATURE].ird'\n\
	ird_tools.exe rename [ird_path1] [ird_path2] ...\n\n\
Note : It also support directory as ird_path, it will search inside recursively\n");
	
	exit(0);
}

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
	
	sprintf(IRD_LOG, "%s.log.txt", IRD_PATH);
	sprintf(IRD_HEADER, "%s.header.bin", IRD_PATH);
	sprintf(IRD_FOOTER, "%s.footer.bin", IRD_PATH);
	sprintf(IRD_DISC_KEY, "%s.disc.key", IRD_PATH);

	print_verbose("GZ_decompress7 header %X", ird->HeaderLength);
	ret = GZ_decompress7((char *) ird->Header, ird->HeaderLength, IRD_HEADER);
	if( ret != Z_OK ) {
		printf("Error : failed to decompress header (%s)", ret);
		FREE_IRD(ird);
		return;
	}
	
	print_verbose("GZ_decompress7 footer");
	ret = GZ_decompress7((char *) ird->Footer, ird->FooterLength, IRD_FOOTER);
	if( ret != Z_OK ) {
		printf("Error : failed to decompress footer (%s)", ret);
		FREE_IRD(ird);
		return;
	}
	
	print_verbose("IRD_GetFilesPath");
	IRD_GetFilesPath(IRD_HEADER, ird);
	
	
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
	
	FILE *log=NULL;
	log=fopen(IRD_LOG, "w");
	if(log==NULL) {
		printf("Error : failed to open %s", IRD_LOG);
		FREE_IRD(ird);
		return;
	}
	
	sprintf(msg, "Game Name : %s\nGame ID : %s\nUpdate : %s\nGame Version : %s\nApp Version : %s\n", ird->GameName, ird->GameId, ird->UpdateVersion, ird->GameVersion, ird->AppVersion);
	fputs(msg, log);
	sprintf(msg, "Files Number = %d\n", ird->FileHashesNumber);
	fputs(msg, log);
	
	fputs("_______________________________________________________________ _ _ _\n", log);
	fputs("                                  |                 |\n", log);
	fputs(" MD5                              | SECTOR          | PATH\n", log);
	fputs("__________________________________|_________________|__________ _ _ _\n", log);
	fputs("                                  |                 |\n", log);
	for(i=0; i<ird->FileHashesNumber; i++) {
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
	}
	fputs("__________________________________|_________________|__________ _ _ _\n\n", log);
	
	sprintf(msg, "Region Number = %d\n", ird->RegionHashesNumber);
	fputs(msg, log);
	fputs("_________________________________________________________\n", log);
	fputs("                                  |                      |\n", log);
	fputs("  MD5                             | REGION               |\n", log);
	fputs("__________________________________|______________________|\n", log);
	fputs("                                  |                      |\n", log);
	for(i=0; i<ird->RegionHashesNumber; i++) {
		sprintf(msg, " %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X | %-20d |\n", 
						ird->RegionHashes[i][0x0],
						ird->RegionHashes[i][0x1],
						ird->RegionHashes[i][0x2],
						ird->RegionHashes[i][0x3],
						ird->RegionHashes[i][0x4],
						ird->RegionHashes[i][0x5],
						ird->RegionHashes[i][0x6],
						ird->RegionHashes[i][0x7],
						ird->RegionHashes[i][0x8],
						ird->RegionHashes[i][0x9],
						ird->RegionHashes[i][0xA],
						ird->RegionHashes[i][0xB],
						ird->RegionHashes[i][0xC],
						ird->RegionHashes[i][0xD],
						ird->RegionHashes[i][0xE],
						ird->RegionHashes[i][0xF], i+1);
		fputs(msg, log);
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
	
	
	u32 meta_sig = IRD_meta_sig(ird);
	u32 files_sig = IRD_files_sig(ird);
	u32 extra_sig = IRD_extra_sig(ird);
	u32 keys_sig = IRD_keys_sig(ird);
	if( !meta_sig || !files_sig || !extra_sig || !keys_sig) {
		FREE_IRD(ird);
		return;
	}
	
	sprintf(msg, "MGZ_SIG = %08X_%08X_%08X_%08X\n", meta_sig, files_sig, extra_sig, keys_sig);
	fputs(msg, log);
	
	fclose(log);
	
	FREE_IRD(ird);
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
	mkdir(TempDir);
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

u8 is_dir(char *path)
{
	struct stat path_stat;
    stat(path, &path_stat);
    return S_ISDIR(path_stat.st_mode);
}

void do_task(char *ird_path, u8 extract)
{
	DIR *d;
	struct dirent *dir;
	
	char path[512];
	strcpy(path, ird_path);
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
			
			if(is_dir(temp)) do_task(temp, extract);
			else {
				int l = strlen(temp);
				if( 	temp[l-4] != '.'
					||	temp[l-3] != 'i'
					||	temp[l-2] != 'r'
					||	temp[l-1] != 'd' ) continue;
				
				if(extract) IRD_extract(temp);
				else 		IRD_rename(temp);
			}
		}
		closedir(d);
	} else {
		if(extract) IRD_extract(path);
		else 		IRD_rename(path);
	}
}

u8 verbose=0;
int main (int argc, char **argv)
{	
	if(argc==1) print_help();
	int i;
	
	u8 extract=1;
	verbose=0;
	
	int args = 1;
	if(strcmp(argv[args], "verbose") == 0){
		verbose=1;
		args++;
	}
	
	if(strcmp(argv[args], "rename") == 0){
		extract=0;
		args++;
	}
	
	
	for(i=args;i<argc;i++) {
		do_task(argv[i], extract);
	}
	
	rmdir("temp");
	
	return 0;
}