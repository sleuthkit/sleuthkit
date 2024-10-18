/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk_base_i.h"

#ifndef HAVE_STRNLEN

#include <string.h>

size_t
strnlen(const char* s, size_t maxlen) {
  const char* const z = memchr(s, 0, maxlen);
  return z ? (size_t) (z - s) : maxlen;
}

#endif
