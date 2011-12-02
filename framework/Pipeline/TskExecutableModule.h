/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#ifndef _TSK_EXECUTABLEMODULE_H
#define _TSK_EXECUTABLEMODULE_H

#include "TskModule.h"

/**
 * An Executable Module supports launching a process to perform
 * some analysis on a File
 */
class TSK_FRAMEWORK_API TskExecutableModule: public TskModule
{
public:
    // Default Constructor
    TskExecutableModule();

    // Destructor
    virtual ~TskExecutableModule();

    virtual Status run(TskFile* fileToAnalyze);

    /// Set the path of the executable to run.
    virtual void setPath(const std::string& location);

    /// Set the output location
    void setOutput(const std::string& outFile);

    std::string getOutput() const;

private:
    std::string m_output;

};

#endif
