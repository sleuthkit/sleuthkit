/*
 * The Sleuth Kit 
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2007-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk_base_i.h"

/** \file tsk_stack.c
 * Contains the functions to create and maintain a stack, which supports basic
 * popping, pushing, and searching.  These are used for finding loops when
 * recursing structures */


/**
 * \ingroup baselib
 * Create a TSK_STACK structure
 * @returns Pointer to structure or NULL on error
 */
TSK_STACK *
tsk_stack_create()
{
    TSK_STACK *tsk_stack;
    if ((tsk_stack = (TSK_STACK *) tsk_malloc(sizeof(TSK_STACK))) == NULL) {
        return NULL;
    }

    tsk_stack->len = 64;
    tsk_stack->top = 0;
    if ((tsk_stack->vals =
            (uint64_t *) tsk_malloc(tsk_stack->len * sizeof(uint64_t))) ==
        NULL) {
        free(tsk_stack);
        return NULL;
    }
    return tsk_stack;
}

/**
 * \ingroup baselib
 * Push a value to the top of TSK_STACK.
 * @param a_tsk_stack Pointer to stack to push onto
 * @param a_val Value to push on
 * @returns 1 on error 
 */
uint8_t
tsk_stack_push(TSK_STACK * a_tsk_stack, uint64_t a_val)
{
    if (a_tsk_stack->top == a_tsk_stack->len) {
        a_tsk_stack->len += 64;
        if ((a_tsk_stack->vals =
                (uint64_t *) tsk_realloc((char *) a_tsk_stack->vals,
                    a_tsk_stack->len * sizeof(uint64_t))) == NULL) {
            return 1;
        }
    }
    a_tsk_stack->vals[a_tsk_stack->top++] = a_val;
    return 0;
}

/**
 * \ingroup baselib
 * Pop a value from the top of the stack.
 * @param a_tsk_stack Stack to pop from
 */
void
tsk_stack_pop(TSK_STACK * a_tsk_stack)
{
    a_tsk_stack->top--;
}

/**
 * \ingroup baselib
 * Search a TSK_STACK for a given value
 * @param a_tsk_stack Stack to search
 * @param a_val Value to search for 
 * @returns 1 if found and 0 if not
 */
uint8_t
tsk_stack_find(TSK_STACK * a_tsk_stack, uint64_t a_val)
{
    size_t i;

    for (i = 0; i < a_tsk_stack->top; i++) {
        if (a_tsk_stack->vals[i] == a_val)
            return 1;
    }
    return 0;
}

/**
 * \ingroup baselib
 * Free an allocated TSK_STACK structure
 * @param a_tsk_stack Stack to free
 */
void
tsk_stack_free(TSK_STACK * a_tsk_stack)
{
    free(a_tsk_stack->vals);
    free(a_tsk_stack);
}
