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
    int do_update = 0;

    char _key[OS_ACM_MAXKEY];

    char *hash_line;
    char hash_buffer[OS_ACM_MAXELM];
    int  hash_field = 0;
    int  hash_idx = 0;

    char elm_dstuser[OS_ACM_MAXELM];
    char elm_srcuser[OS_ACM_MAXELM];
    char elm_dstip[OS_ACM_MAXELM];
    char elm_srcip[OS_ACM_MAXELM];
    char elm_data[OS_ACM_MAXELM];
    char tmp_expire[OS_ACM_MAXELM];
    int  elm_stored = 0;
    int  elm_current = 0;
    int  result = 0;
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

    // Accumulator Attempt
    acm_lookups++;

    // Purge the cache as needed
    Accumulate_CleanUp();

    // Initialize variables

    // Timing data
    gettimeofday(&tp, NULL);
    elm_current = tp.tv_sec;

    // Ensure elements are empty
    memset(tmp_expire, 0,OS_ACM_MAXELM);
    memset(elm_dstuser,0,OS_ACM_MAXELM);
    memset(elm_srcuser,0,OS_ACM_MAXELM);
    memset(elm_dstip,  0,OS_ACM_MAXELM);
    memset(elm_srcip,  0,OS_ACM_MAXELM);
    memset(elm_data,   0,OS_ACM_MAXELM);

    // Ensure hash_buffer is empty
    memset(hash_buffer, 0, OS_ACM_MAXELM);

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
    if((hash_line = (char *)OSHash_Get(acm_store, _key)) != NULL) {
        debug2("accumulator: DEBUG: Lookup for '%s' found a stored value!", _key);
        debug2("accumulator: DEBUG: That value is '%s'", hash_line);
        do_update = 1;
        int i;
        // Yes, we have to go past the last character to the \0
        for ( i = 0; i <= strnlen(hash_line,OS_ACM_MAXELM); i++ ) {
            // Skip new lines
            if( hash_line[i] == '\r' || hash_line[i] == '\n' ) continue;
            // Check to set values
            if( hash_line[i] == '|' || hash_line[i] == '\0') {
                switch( hash_field ) {
                    case ACM_EXPIRE:
                        result = strncpy(tmp_expire, hash_buffer, OS_ACM_MAXELM ) == NULL ? -1 : 0;
                        break;
                    case ACM_DSTUSER:
                        result = strncpy(elm_dstuser, hash_buffer, OS_ACM_MAXELM ) == NULL ? -1 : 0;                        break;
                        break;
                    case ACM_SRCUSER:
                        result = strncpy(elm_srcuser, hash_buffer, OS_ACM_MAXELM ) == NULL ? -1 : 0;                        break;
                        break;
                    case ACM_DSTIP:
                        result = strncpy(elm_dstip, hash_buffer, OS_ACM_MAXELM ) == NULL ? -1 : 0;                        break;
                        break;
                    case ACM_SRCIP:
                        result = strncpy(elm_srcip, hash_buffer, OS_ACM_MAXELM ) == NULL ? -1 : 0;                        break;
                        break;
                    case ACM_DATA:
                        result = strncpy(elm_data, hash_buffer, OS_ACM_MAXELM ) == NULL ? -1 : 0;                        break;
                        break;
                    default:
                        result = -2;
                        break;
                }
                // Check the result of our operation
                if( result == -1 ) {
                    debug2("accumulator: DEBUG: Error bad field index -> %d", hash_field);
                    break;
                }
                else if( result == -1 ) {
                    debug2("accumulator: DEBUG: Error copying hash_buffer into a element %d", hash_field);
                }
                // Move on to the next field
                hash_field++;
                hash_idx=0;
                memset(hash_buffer, 0, OS_ACM_MAXELM);
            }
            else {
                hash_buffer[hash_idx] = hash_line[i];
                hash_idx++;
            }
        }
        if( strnlen(tmp_expire, OS_ACM_MAXELM) > 0 ) {
            elm_stored = atoi(tmp_expire);
            if( elm_stored > 0 && elm_stored < elm_current - ACM_EXPIRE_ELM ) {
                char* del;
                if( (del = OSHash_Delete(acm_store, _key)) != NULL ) {
                    debug1("accumulator: DEBUG: Deleted expired hash entry for '%s'", _key);
                    free(del);
                }
            }
        }
    }

    if( elm_stored > 0 && elm_stored >= elm_current - ACM_EXPIRE_ELM ) {
        // Update the event
        if (acm_str_replace(&lf->dstuser,elm_dstuser) == 0)
            debug2("accumulator: DEBUG: (%s) updated dstuser to %s", _key, lf->dstuser);

        if (acm_str_replace(&lf->srcuser,elm_srcuser) == 0)
            debug2("accumulator: DEBUG: (%s) updated srcuser to %s", _key, lf->srcuser);

        if (acm_str_replace(&lf->dstip,elm_dstip) == 0)
            debug2("accumulator: DEBUG: (%s) updated dstip to %s", _key, lf->dstip);

        if (acm_str_replace(&lf->srcip,elm_srcip) == 0)
            debug2("accumulator: DEBUG: (%s) updated srcip to %s", _key, lf->srcip);

        if (acm_str_replace(&lf->data,elm_data) == 0)
            debug2("accumulator: DEBUG: (%s) updated data to %s", _key, lf->data);
    }

    // Setup the data for storage
    char* data = malloc(OS_ACM_MAXDATA);
    result = snprintf(data, OS_ACM_MAXDATA, "%d|%s|%s|%s|%s|%s",
            elm_current,
            (lf->dstuser != NULL)?lf->dstuser:"",
            (lf->srcuser != NULL)?lf->srcuser:"",
            (lf->dstip   != NULL)?lf->dstip:"",
            (lf->srcip   != NULL)?lf->srcip:"",
            (lf->data    != NULL)?lf->data:""
            );
    if( result < 0 || result >= OS_ACM_MAXDATA) {
        // TODO: ERROR HERE
        debug1("accumulator: DEBUG: Error packing data for %s", _key);
        return lf;
    }
    else {
        debug2("accumulator: DEBUG: SET '%s' => %s", _key, data);
    }
    // Update or Add to the hash
    if( do_update == 1 ) {
        // Update the hash entry
        if(OSHash_Update(acm_store, _key, data) <= 1) {
            debug2("accumulator: DEBUG: Updated stored data for %s", _key);
        }
    }
    else {
        if(OSHash_Add(acm_store, _key, data) <= 1) {
            debug2("accumulator: DEBUG: Updated stored data for %s", _key);
        }
    }

    return lf;
}

void Accumulate_CleanUp() {
    struct timeval tp;
    int current_ts = 0;
    int expired = 0;

    OSHashNode *curr;
    char tmp_expire[OS_ACM_MAXELM];
    int  elm_expire = 0;
    char *data;
    char *key;
    int ti;

    // Initialize Variables
    gettimeofday(&tp, NULL);
    current_ts = tp.tv_sec;

    // Do we really need to purge?
    if( acm_lookups < ACM_PURGE_COUNT && acm_purge_ts < current_ts + ACM_PURGE_INTERVAL ) {
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
            data = (char *) curr->data;
            key  = (char *) curr->key;
            debug2("accumulator: DEBUG: CleanUp() evaluating cache: %s => %s", key, data);
            /* check for a valid element */
            if( data != NULL && strnlen(data, OS_ACM_MAXELM) > 0 ) {
                memset(tmp_expire, 0, OS_ACM_MAXELM);
                elm_expire = 0;
                int i;
                for ( i = 0; i < OS_ACM_MAXELM + 1; i ++ ) {
                    if( data[i] == '|' ) {
                        // First Bar, read expire
                        elm_expire = atoi(tmp_expire);
                        break;
                    }
                    else {
                        tmp_expire[i] = data[i];
                    }
                }
                /* Check for expiration */
                debug2("accumulator: DEBUG: CleanUp() elm:%d, curr:%d", elm_expire, current_ts);
                if( elm_expire < current_ts - ACM_EXPIRE_ELM ) {
                    debug2("accumulator: DEBUG: CleanUp() Expiring '%s'", key);
                    char* del;
                    if( (del = OSHash_Delete(acm_store, key)) != NULL ) {
                        free(del);
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

int acm_str_replace(char **dst, const char* src) {
    int result = 0;

    if( src == NULL || (dst != NULL && *dst != NULL && **dst != '\0') ) {
        return 0;
    }

    int slen = strnlen(src, OS_ACM_MAXELM);

    if ( slen == 0 ) {
        return 0;
    }

    free(*dst);
    *dst = malloc(slen); // This will be free'd by the FreeEvent function
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
