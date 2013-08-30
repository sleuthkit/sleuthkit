/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** 
 * \file SummaryReport.h 
 * Contains the declaration of a function that creates a blackboard artifacts report.
 */

// C/C++ standard library includes 
#include <string>

namespace TskSummaryReport
{
    void generateReport(const std::string &reportPath);
}
