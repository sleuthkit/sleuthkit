
/***************************************************************************
** This data and information is proprietary to, and a valuable trade secret
** of, Basis Technology Corp.  It is given in confidence by Basis Technology
** and may only be used as permitted under the license agreement under which
** it has been distributed, and in no other way.
**
** Copyright (c) 2016 Basis Technology Corp. All rights reserved.
**
** The technical data and information provided herein are provided with
** `limited rights', and the computer software provided herein is provided
** with `restricted rights' as those terms are defined in DAR and ASPR
** 7-104.9(a).
***************************************************************************/

#pragma once

#include <string>

class ScheduledTaskAction {
public:
    ScheduledTaskAction(std::string progName, std::string exePathName) {
        m_progName = progName;
        m_exePathName = exePathName;

        m_args.clear();
        m_workingDir.clear();
    }

    // Copy constructor
    ScheduledTaskAction(const ScheduledTaskAction &other) {
        m_progName = other.getProgName();
        m_exePathName = other.getEXEPathname();
        m_args = other.getArgs();
        m_workingDir = other.getWorkingDir();
    }

    void setWorkingDir(std::string aDir) { m_workingDir = aDir; }
    void setArgs(std::string aArgs) { m_args = aArgs; }

    std::string getProgName() const { return m_progName; };
    std::string getEXEPathname() const { return m_exePathName; };
    std::string getArgs() const { return m_args; };
    std::string getWorkingDir() const { return m_workingDir; };

private:
    std::string m_progName;		// name only
    std::string m_exePathName;   // full path and name
    std::string m_args;			// arguments 
    std::string m_workingDir;	// optional working dir may be specified.
};