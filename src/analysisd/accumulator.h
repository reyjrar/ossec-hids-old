/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef __ACCUMULATOR_H

#define __ACCUMULATOR_H

/* Accumulator queues */
#ifdef TESTRULE
  #define ACM_CACHE "var/accumulator-cache"
#else
  #define ACM_CACHE "/var/accumulator-queue"
#endif

#include "eventinfo.h"

/* Accumulator Max Values */
#define OS_ACM_MAXKEY 256
#define OS_ACM_MAXELM 81
#define OS_ACM_MAXDATA 2048

typedef struct _OS_ACM_Store {
    int timestamp;
    char *dstuser;
    char *srcuser;
    char *dstip;
    char *srcip;
    char *data;
} OS_ACM_Store;

/* Accumulator Constants */
#define OS_ACM_EXPIRE_ELM      300
#define OS_ACM_PURGE_INTERVAL  600
#define OS_ACM_PURGE_COUNT     100

/* Accumulator Functions */
int Accumulate_Init();
Eventinfo* Accumulate(Eventinfo *lf);
void Accumulate_CleanUp();

/* Internal Functions */
int acm_str_replace(char **dst, const char* src);
void FreeACMStore(OS_ACM_Store *obj);

#endif
