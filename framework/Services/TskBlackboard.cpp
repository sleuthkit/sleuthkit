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
const string TskBlackboard::TSK_USERNAME = "USERNAME"; ///< String of a user name.  Use TskBlackboard::TSK_DOMAIN to store the domain that the username is from (if it is known). 
const string TskBlackboard::TSK_PASSWORD = "PASSWORD"; ///< String of a password that was found.  Use TskBlackboard::TSK_USERNAME and TskBlackboard::TSK_DOMAIN to link the password to a given user and site. 
const string TskBlackboard::TSK_NAME_PERSON = "NAME_PERSON";     ///< String of a person name 
const string TskBlackboard::TSK_DEVICE_MODEL = "MODEL"; ///< String of manufactorer name of device that was connected (or somehow related to) the data being analyzed
const string TskBlackboard::TSK_DEVICE_MAKE = "MAKE";  ///< String of make of a device that was connected (or somehow related to) the data being analyzed
const string TskBlackboard::TSK_DEVICE_ID = "ID";   ///< String of ID of a device that was connected (or somehow releated to) the data being analyzed
const string TskBlackboard::TSK_RECENTLYUSED = "RECENTLYUSED"; ///< STRING: TBD
const string TskBlackboard::TSK_KEYWORD = "KEYWORD";  ///< STRING: Keyword that was found in this file. 
const string TskBlackboard::TSK_EMAIL = "EMAIL";    ///< String of e-mail address in the form of user@host.com
const string TskBlackboard::TSK_URL = "URL";      ///< String of a URL, should start with http:// or ftp:// etc.  You should also make a TskBlackoard::TSK_DOMAIN entry for the base domain name. 
const string TskBlackboard::TSK_URL_HISTORY = "HISTORY"; ///< STRING: 
const string TskBlackboard::TSK_DOMAIN = "DOMAIN";   ///< String of a DNS Domain name, e.g. sleuthkit.org  use TskBlackboad::TSK_URL for a full URL.
const string TskBlackboard::TSK_HASH_MD5 = "HASH_MD5"; ///< STRING: MD5 hash
const string TskBlackboard::TSK_HASH_SHA1 = "HASH_SHA1";     ///< STRING: SHA1 hash
const string TskBlackboard::TSK_HASH_SHA2_256 = "HASH_SHA2_256"; ///< STRING: SHA2 256 bit hash
const string TskBlackboard::TSK_HASH_SHA2_512 = "HASH_SHA2_512"; ///< STRING: SHA2 512 bit hash
const string TskBlackboard::TSK_TEXT = "TEXT";      ///< String of text extrated from a file.
const string TskBlackboard::TSK_TEXT_LANGUAGE = "TEXT_LANGUAGE";  ///< String of the detected language in ISO 639-3 language code of TskBlackboard::TSK_TEXT data.
const string TskBlackboard::TSK_ENTROPY = "ENTROPY";   ///< DOUBLE: Entropy value of file
const string TskBlackboard::TSK_PROGRAM_NAME = "PROGRAM_NAME";   ///< String of name of a program that was installed on the system
const string TskBlackboard::TSK_HASHSET_NAME = "HASHSET_NAME";  ///< String of name of the hashset if a file was found in it
