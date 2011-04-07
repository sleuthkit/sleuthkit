/*
 * The Sleuth Kit 
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2007-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk_base_i.h"

/** \file tsk_list.c
 * tsk_lists are a linked list of buckets that store a key in REVERSE sorted order.
 * They are used to keep track of data as we walk along and prevent loops
 * from data corruption.   Note that the len value is actually negative.  An entry
 * with a key of 6 and a length of 2 covers the range of 5 to 6. 
 */

/*
 * Create a list with teh first entry defined
 * @param a_key Key for initial entry
 * @returns newly created entry
 */
static TSK_LIST *
tsk_list_create(uint64_t a_key)
{
    TSK_LIST *ent;
    if ((ent = (TSK_LIST *) tsk_malloc(sizeof(TSK_LIST))) == NULL) {
        return NULL;
    }

    ent->key = a_key;
    ent->next = NULL;
    ent->len = 1;

    return ent;
}

/**
 * \ingroup baselib
 * Add an entry to a TSK_LIST (and create one if one does not exist)
 * @param a_tsk_list_head Pointer to pointer for head of list (can point to NULL if no list exists).  
 * @param a_key Value to add to list
 * @returns 1 on error
 */
uint8_t
tsk_list_add(TSK_LIST ** a_tsk_list_head, uint64_t a_key)
{
    TSK_LIST *tmp;

    /* If the head is NULL, then create an entry */
    if (*a_tsk_list_head == NULL) {
        TSK_LIST *ent;
        /*
           if (tsk_verbose)
           fprintf(stderr, "entry %" PRIu64 " is first on list\n", a_key);
         */
        if ((ent = tsk_list_create(a_key)) == NULL)
            return 1;

        *a_tsk_list_head = ent;
        return 0;
    }

    /* If the new key is larger than the head, make it the head */
    if (a_key > (*a_tsk_list_head)->key) {
        /*
           if (tsk_verbose)
           fprintf(stderr,
           "entry %" PRIu64 " added to head before %" PRIu64 "\n",
           a_key, (*a_tsk_list_head)->key);
         */

        // If we can, update the length of the existing list entry
        if (a_key == (*a_tsk_list_head)->key + 1) {
            (*a_tsk_list_head)->key++;
            (*a_tsk_list_head)->len++;
        }
        else {
            TSK_LIST *ent;
            if ((ent = tsk_list_create(a_key)) == NULL)
                return 1;
            ent->next = *a_tsk_list_head;
            *a_tsk_list_head = ent;
        }
        return 0;
    }
    // get rid of duplicates
    else if (a_key == (*a_tsk_list_head)->key) {
        return 0;
    }

    /* At the start of this loop each time, we know that the key to add 
     * is smaller than the entry being considered (tmp) */
    tmp = *a_tsk_list_head;
    while (tmp != NULL) {

        /* First check if this is a duplicate and contained in tmp */
        if (a_key > (tmp->key - tmp->len)) {
            return 0;
        }
        /* Can we append it to the end of tmp? */
        else if (a_key == (tmp->key - tmp->len)) {
            // do a sanity check on the next entry
            if ((tmp->next) && (tmp->next->key == a_key)) {
                // @@@ We could fix this situation and remove the next entry...
                return 0;
            }
            tmp->len++;
            return 0;
        }

        /* The key is less than the current bucket and can't be added to it.
         * check if we are at the end of the list yet */
        else if (tmp->next == NULL) {
            TSK_LIST *ent;

            /*
               if (tsk_verbose)
               fprintf(stderr, "entry %" PRIu64 " added to tail\n",
               a_key);
             */

            if ((ent = tsk_list_create(a_key)) == NULL)
                return 1;
            tmp->next = ent;

            return 0;
        }
        // can we prepend it to the next bucket?
        else if (a_key == tmp->next->key + 1) {
            tmp->next->key++;
            tmp->next->len++;
            return 0;
        }
        // do we need a new bucket in between?
        else if (a_key > tmp->next->key) {
            TSK_LIST *ent;

            /*
               if (tsk_verbose)
               fprintf(stderr,
               "entry %" PRIu64 " added before %" PRIu64 "\n",
               a_key, tmp->next->key);
             */

            if ((ent = tsk_list_create(a_key)) == NULL)
                return 1;

            ent->next = tmp->next;
            tmp->next = ent;
            return 0;
        }
        else if (a_key == tmp->next->key) {
            return 0;
        }
        tmp = tmp->next;
    }
    return 0;
}

/**
 * \ingroup baselib
 * Search a TSK_LIST for the existence of a value.
 * @param a_tsk_list_head Head of list to search
 * @param a_key Value to search for
 * @returns 1 if value is found and 0 if not
 */
uint8_t
tsk_list_find(TSK_LIST * a_tsk_list_head, uint64_t a_key)
{
    TSK_LIST *tmp;

    tmp = a_tsk_list_head;
    while (tmp != NULL) {
        // check this bucket
        // use the key+1 and then subtract for unsigned cases when key-len == -1
        if ((a_key <= tmp->key) && (a_key >= tmp->key + 1 - tmp->len))
            return 1;

        // Have we passed any potential buckets?
        else if (a_key > tmp->key)
            return 0;

        tmp = tmp->next;
    }
    return 0;
}

/**
 * \ingroup baselib
 * Free a TSK_LIST.
 * @param a_tsk_list_head Head of list to free
 */
void
tsk_list_free(TSK_LIST * a_tsk_list_head)
{
    TSK_LIST *tmp;

    while (a_tsk_list_head) {
        tmp = a_tsk_list_head->next;
        free(a_tsk_list_head);
        a_tsk_list_head = tmp;
    }
}
