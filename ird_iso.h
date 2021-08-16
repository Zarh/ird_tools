#ifndef _IRD_ISO_H
#define _IRD_ISO_H

#include "ird_build.h"
#include "ird_gz.h"
#include "md5.h"

u8 IRD_GetFilesPath(char *ISO_PATH, ird_t *ird);
u8 IRD_GetRegionBoundaries(char *ISO_PATH, ird_t *ird);
u8 GetPVD(char *ISO, u8 *PVD);

#endif

