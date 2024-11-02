/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (C) 2024 Sleuth Kit Labs, LLC
 * Copyright (c) 2006-2023 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * mmls - list media management structure contents.
 *      - This is main() that gets linked for the stand-alone program
 *
 */
#include "tsk/tsk_tools_i.h"
#include "mmls.h"

int
main(int argc, char **argv1)
{
    return mmls_main(argc, argv1);
}
