/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#pragma once

#include <string>

#include "tsk/libtsk.h"

/**
* Defines the Drive Utilities
*
*/
class DriveUtil {
public:
    static bool cwdIsFAT(std::wstring &cwd);
    static TSK_IMG_INFO *addFSFromImage(const TSK_TCHAR *image);
    static int isDriveLocked(const std::string &driveLetter);
    static bool hasBitLockerOrLDM(const std::string &systemDriveLetter);
    static BOOL getPhysicalDrives(std::vector<std::wstring> &phyiscalDrives);

private:
    static bool driveIsFAT(wchar_t *drive);
    static long wmi_init(const std::wstring& wmiNamespace, IWbemLocator **ppWbemLocator, IWbemServices **ppWbemServices);
    static int wmi_close(IWbemLocator **ppWbemLocator, IWbemServices **ppWbemServices);
    static int checkDriveForBitlocker(const std::string &driveLetter);
    static int checkDriveForLDM(const std::string &driveLetter);
};
