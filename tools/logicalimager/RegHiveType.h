/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
* \file RegHiveType.h
* Contains the definitions for Registry Hive Type.
*/

#pragma once

namespace RegHiveType {
  enum Enum {
    SYSTEM,
    SAM,
    SECURITY,
    SOFTWARE,
    NTUSER,
    USRCLASS,
    UNKNOWN
  };

  static char String[][100] = {
    "SYSTEM",
    "SAM",
    "SECURITY",
    "SOFTWARE",
    "NTUSER",
    "USRCLASS",
    "UNKNOWN"
  };
}
