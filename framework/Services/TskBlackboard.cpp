/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "TskBlackboard.h"

/* Note that the below comments are the only documentation for the standard types.
 * Please ensure that all types are documented. */
const string TskBlackboard::TSK_DATETIME = "DATETIME"; ///< INT32: GMT based Unix time, defines number of secords elapsed since UTC Jan 1, 1970.
const string TskBlackboard::TSK_GEO = "GEO";      ///< STRING: TBD
const string TskBlackboard::TSK_USERNAME = "USERNAME"; ///< STRING: TBD
const string TskBlackboard::TSK_PASSWORD = "PASSWORD"; ///< STRING: TBD
const string TskBlackboard::TSK_NAME = "NAME";     ///< STRING: TBD
const string TskBlackboard::TSK_DEVICE_MODEL = "MODEL"; ///< STRING: TBD
const string TskBlackboard::TSK_DEVICE_MAKE = "MAKE";  ///< STRING: TBD
const string TskBlackboard::TSK_DEVICE_ID = "ID";   ///< STRING: TBD
const string TskBlackboard::TSK_RECENTLYUSED = "RECENTLYUSED"; ///< STRING: TBD
const string TskBlackboard::TSK_KEYWORD = "KEYWORD";  ///< STRING: Keyword that was found in this file. 
const string TskBlackboard::TSK_EMAIL = "EMAIL";    ///< STRING: e-mail address in the form of user@host.com
const string TskBlackboard::TSK_URL = "URL";      ///< STRING: URL, should start with http:// or ftp:// etc.
const string TskBlackboard::TSK_URL_HISTORY = "HISTORY"; ///< STRING: 
const string TskBlackboard::TSK_DOMAIN = "DOMAIN";   ///< STRING: DNS Domain name, e.g. sleuthkit.org
const string TskBlackboard::TSK_HASH_MD5 = "MD5"; ///< STRING: MD5 hash
const string TskBlackboard::TSK_HASH_SHA1 = "SHA1";     ///< STRING: SHA1 hash
const string TskBlackboard::TSK_HASH_SHA2_256 = "256"; ///< STRING: SHA2 256 bit hash
const string TskBlackboard::TSK_HASH_SHA2_512 = "512"; ///< STRING: SHA2 512 bit hash
const string TskBlackboard::TSK_TEXT = "TEXT";      ///< STRING: Text extracted from a document
const string TskBlackboard::TSK_TEXT_LANGUGE = "LANGUGE";  ///< STRING: Language of TEXT, should use ISO 639-3 langage code
const string TskBlackboard::TSK_ENTROPY = "ENTROPY";   ///< DOUBLE: Entropy value of file
const string TskBlackboard::TSK_PROGRAM_NAME = "PROGRAM";   ///< STRING: TBD
const string TskBlackboard::TSK_HASHSET_NAME = "HASHSETNAME";  ///< STRING: TBD