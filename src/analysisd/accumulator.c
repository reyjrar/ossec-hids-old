/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


/* Accumulator Functions which accumulate objects based on an id
*/

#include <sys/time.h>
#include "shared.h"
#include "accumulator.h"
#include "eventinfo.h"

OSList *acm_list = NULL;
OSHash *acm_store = NULL;

// Counters for Purging
int  acm_lookups = 0;
int  acm_purge_ts = 0;

/** int Accumulator_Init()
 * Starts the Accumulator module.
 */
int Accumulate_Init()
{
    struct timeval tp;

    /* Creating store data */
    acm_store = OSHash_Create();
    if(!acm_store)
    {
        merror(LIST_ERROR, ARGV0);
        return(0);
    }
    if(!OSHash_setSize(acm_store, 2048))
    {
        merror(LIST_ERROR, ARGV0);
        return(0);
    }

    /* Default Expiry */
    gettimeofday(&tp, NULL);
    acm_purge_ts = tp.tv_sec;

    debug1("%s: DEBUG: Accumulator Init completed.", ARGV0);
    return(1);
}

/* Accumulate v0.1
 *   Accumulate data from events sharing the same id
 */
Eventinfo* Accumulate(Eventinfo *lf)
{
    // Declare our variables
    int result;
    int do_update = 0;

    char _key[OS_ACM_MAXKEY];
    OS_ACM_Store *stored_data;

    // Timing Variables
    int  current_ts;
    struct timeval tp;


    // We need an ID to use the accumulator
    if( lf->id == NULL ) {
        // TODO: ERROR HERE
        debug1("accumulator: DEBUG: No id available");
        return lf;
    }
    if( lf->decoder_info == NULL ) {
        // TODO: ERROR HERE
        debug1("accumulator: DEBUG: No decoder_info available");
        return lf;
    }
    if( lf->decoder_info->name == NULL ) {
        // TODO: ERROR HERE
        debug1("accumulator: DEBUG: No decoder name available");
        return lf;
    }

    // Purge the cache as needed
    Accumulate_CleanUp();

    // Initialize variables

    // Timing data
    gettimeofday(&tp, NULL);
    current_ts = tp.tv_sec;

    /* Accumulator Key */
    result = snprintf(_key, OS_FLSIZE, "%s %s %s",
            lf->hostname,
            lf->decoder_info->name,
            lf->id
            );
    if( result < 0 || result >= sizeof(_key) ) {
        // TODO: ERROR HERE
        debug1("accumulator: DEBUG: error setting accumulator key, id:%s,name:%s", lf->id, lf->decoder_info->name);
        return lf;
    }

    /** Checking if acm is already present **/
    if((stored_data = (OS_ACM_Store *)OSHash_Get(acm_store, _key)) != NULL) {
        debug2("accumulator: DEBUG: Lookup for '%s' found a stored value!", _key);
        do_update = 1;

        if( stored_data->timestamp > 0 && stored_data->timestamp < current_ts - OS_ACM_EXPIRE_ELM ) {
            OS_ACM_Store *del;
            if( (del = OSHash_Delete(acm_store, _key)) != NULL ) {
                debug1("accumulator: DEBUG: Deleted expired hash entry for '%s'", _key);
                FreeACMStore(del);
                FreeACMStore(stored_data);
            }
        }
        else {
            // Update the event
            if (acm_str_replace(&lf->dstuser,stored_data->dstuser) == 0)
                debug2("accumulator: DEBUG: (%s) updated lf->dstuser to %s", _key, lf->dstuser);

            if (acm_str_replace(&lf->srcuser,stored_data->srcuser) == 0)
                debug2("accumulator: DEBUG: (%s) updated lf->srcuser to %s", _key, lf->srcuser);

            if (acm_str_replace(&lf->dstip,stored_data->dstip) == 0)
                debug2("accumulator: DEBUG: (%s) updated lf->dstip to %s", _key, lf->dstip);

            if (acm_str_replace(&lf->srcip,stored_data->srcip) == 0)
                debug2("accumulator: DEBUG: (%s) updated lf->srcip to %s", _key, lf->srcip);

            if (acm_str_replace(&lf->data,stored_data->data) == 0)
                debug2("accumulator: DEBUG: (%s) updated lf->data to %s", _key, lf->data);
        }
    }
    if ( stored_data == NULL ) {
        os_malloc(sizeof(OS_ACM_Store), stored_data);
    }

    // Store the object in the cache
    stored_data->timestamp = current_ts;
    if (acm_str_replace(&stored_data->dstuser,lf->dstuser) == 0)
        debug2("accumulator: DEBUG: (%s) updated stored_data->dstuser to %s", _key, lf->dstuser);

    if (acm_str_replace(&stored_data->srcuser,lf->srcuser) == 0)
        debug2("accumulator: DEBUG: (%s) updated stored_data->srcuser to %s", _key, lf->srcuser);

    if (acm_str_replace(&stored_data->dstip,lf->dstip) == 0)
        debug2("accumulator: DEBUG: (%s) updated stored_data->dstip to %s", _key, lf->dstip);

    if (acm_str_replace(&stored_data->srcip,lf->srcip) == 0)
        debug2("accumulator: DEBUG: (%s) updated stored_data->srcip to %s", _key, lf->srcip);

    if (acm_str_replace(&stored_data->data,lf->data) == 0)
        debug2("accumulator: DEBUG: (%s) updated stored_data->data to %s", _key, lf->data);

    // Update or Add to the hash
    if( do_update == 1 ) {
        // Update the hash entry
        if(OSHash_Update(acm_store, _key, stored_data) <= 1) {
            debug2("accumulator: DEBUG: Updated stored data for %s", _key);
        }
    }
    else {
        if(OSHash_Add(acm_store, _key, stored_data) <= 1) {
            debug2("accumulator: DEBUG: Added stored data for %s", _key);
        }
    }

    return lf;
}

void Accumulate_CleanUp() {
    struct timeval tp;
    int current_ts = 0;
    int expired = 0;

    OSHashNode *curr;
    OS_ACM_Store *stored_data;
    char *key;
    int ti;

    // Keep track of how many times we're called
    acm_lookups++;

    // Initialize Variables
    gettimeofday(&tp, NULL);
    current_ts = tp.tv_sec;

    // Do we really need to purge?
    if( acm_lookups < OS_ACM_PURGE_COUNT && acm_purge_ts < current_ts + OS_ACM_PURGE_INTERVAL ) {
        return;
    }
    debug1("accumulator: DEBUG: Accumulator_CleanUp() running .. ");

    // Yes, we do.
    acm_lookups = 0;
    acm_purge_ts = current_ts;

    // Loop through the hash
    for ( ti = 0; ti < acm_store->rows; ti++ ) {
        curr = acm_store->table[ti];
        while( curr != NULL ) {
            stored_data = (OS_ACM_Store *) curr->data;
            key  = (char *) curr->key;
            debug2("accumulator: DEBUG: CleanUp() evaluating cached key: %s ", key);
            /* check for a valid element */
            if( stored_data != NULL ) {
                /* Check for expiration */
                debug2("accumulator: DEBUG: CleanUp() elm:%d, curr:%d", stored_data->timestamp, current_ts);
                if( stored_data->timestamp < current_ts - OS_ACM_EXPIRE_ELM ) {
                    debug2("accumulator: DEBUG: CleanUp() Expiring '%s'", key);
                    OS_ACM_Store* del;
                    if( (del = OSHash_Delete(acm_store, key)) != NULL ) {
                        FreeACMStore(del);
                        expired++;
                    }
                    else {
                        debug1("accumulator: DEBUG: CleanUp() failed to find key '%s'", key);
                    }
                }
            }
            curr = curr->next;
        }
    }
    debug2("accumulator: DEBUG: Expired %d elements", expired);
}

void FreeACMStore(OS_ACM_Store *obj) {
    if( obj != NULL ) {
        free(obj->dstuser);
        free(obj->srcuser);
        free(obj->dstip);
        free(obj->srcip);
        free(obj->data);
        free(obj);
    }
}

int acm_str_replace(char **dst, const char* src) {
    int result = 0;

    if( src == NULL || (dst != NULL && *dst != NULL && **dst != '\0') ) {
        return 0;
    }

    int slen = strnlen(src, OS_ACM_MAXELM - 1);

    if ( slen == 0 ) {
        return 0;
    }

    free(*dst);
    *dst = malloc(slen + 1); // This will be free'd by the FreeEvent function
    if( *dst == NULL ) {
        debug2("something bad happend with malloc");
        return -1;
    }

    result = strncpy(*dst, src, strnlen(src, OS_ACM_MAXELM)) == NULL ? -1 : 0;
    if (result < 0)
        debug1("accumulator: DEBUG: error in acm_str_replace()");
    return result;
}

/* EOF */
