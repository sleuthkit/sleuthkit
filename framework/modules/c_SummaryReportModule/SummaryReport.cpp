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
 * \file SummaryReport.cpp 
 * Contains the implementation of a function that creates a blackboard artifacts report.
 */

// TSK Framework includes
#include "tsk/framework/utilities/TskUtilities.h"
#include "tsk/framework/services/TskServices.h"

// Poco includes
#include "Poco/FileStream.h"

// C/C++ standard library includes 
#include <string>
#include <sstream>

namespace
{
    // Convert reserved HTML characters to HTML entities
    std::string HTMLEncode(const std::string &str)
    {
        std::string convertedStr;
        for (size_t i = 0; i < str.size(); i++) 
        {
            if (str[i] == '<')
                convertedStr.append("&lt;");
            else if (str[i] == '>')
                convertedStr.append("&gt;");
            else if (str[i] == '&')
                convertedStr.append("&amp;");
            else if (str[i] == '"')
                convertedStr.append("&quot;");
            else if (str[i] == '\'')
                convertedStr.append("&apos;");
            else
                convertedStr += str[i];
        }
        return convertedStr;
    }

    void addStyle(Poco::FileOutputStream &out)
    {
        out << "<style type=\"text/css\">" << std::endl <<  
            "table.gridtable {" << std::endl <<
            "font-family: verdana,arial,sans-serif;" << std::endl <<
            "font-size:11px;" << std::endl <<
            "color:#333333;" << std::endl <<
            "border-width: 1px;" << std::endl <<
            "border-color: #666666;" << std::endl <<
            "border-collapse: collapse;" << std::endl <<
            "}" << std::endl <<
            "table.gridtable th {" << std::endl <<
            "border-width: 1px;" << std::endl <<
            "padding: 8px;" << std::endl <<
            "border-style: solid;" << std::endl <<
            "border-color: #666666;" << std::endl <<
            "background-color: #dedede;" << std::endl <<
            "}" << std::endl <<
            "table.gridtable td {" << std::endl <<
            "border-width: 1px;" << std::endl <<
            "padding: 8px;" << std::endl <<
            "border-style: solid;" << std::endl <<
            "border-color: #666666;" << std::endl <<
            "background-color: #ffffff;" << std::endl <<
            "}" << std::endl <<
            "h1 {" << std::endl <<
            "font-size: 1.5em;" << std::endl <<
            "color: #000000;" << std::endl <<
            "font-family: Arial, sans-serif;" << std::endl <<
            "}" << std::endl <<

            "h2 {" << std::endl <<
            "font-size: 1.2em;" << std::endl <<
            "color: #000000;" << std::endl <<
            "font-family: Arial, sans-serif;" << std::endl <<
            "}" << std::endl <<

            "h3 {" << std::endl <<
            "margin-left: 0;" << std::endl <<
            "margin-bottom: 0;" << std::endl <<
            "font-size: 1.0em;" << std::endl <<
            "color: #000000;" << std::endl <<
            "font-family: Arial, sans-serif;" << std::endl <<
            "}" << std::endl <<
            "</style>" << std::endl;
    }

    void writeReport(Poco::FileOutputStream &out)
    {
            out << "<html>" << std::endl;
            out << "<head>" << std::endl;
            out << "<meta http-equiv='Content-Type' content='text/html; charset=UTF-8' />" << std::endl;
            addStyle(out);

            out << "<title>Report</title>" << std::endl;
            out << "</head>" << std::endl;
            out << "<body>" << std::endl;

            TskBlackboard &blackboard = TskServices::Instance().getBlackboard();
            TskImgDB &imgdb = TskServices::Instance().getImgDB();
            std::stringstream condition;

            out << "<h1>Sleuth Kit Framework Summary Report</h1>" << std::endl;
            std::vector<std::string> names = imgdb.getImageNames();
            out << "<h2>Image Path: " << names.front() << "</h2>" << std::endl;

            out << "<h2>Image Layout</h2>" << std::endl;
            std::list<TskVolumeInfoRecord> volumeInfoList;
            imgdb.getVolumeInfo(volumeInfoList);

            std::list<TskFsInfoRecord> fsInfoList;
            imgdb.getFsInfo(fsInfoList);
            TskFsInfoRecord fsInfo;

            if (fsInfoList.size() == 0)
            {
                out << "<em>NO FILE SYSTEMS FOUND IN THE DISK IMAGE.</em>" << std::endl;
            }

            out << "<table class=\"gridtable\">" << std::endl;
            out << "<thead>" << std::endl;
            out << "<tr>" << std::endl;
            out << "<th>Start Sector</th>" << std::endl;
            out << "<th>End Sector</th>" << std::endl;
            out << "<th>Partition Type</th>" << std::endl;
            out << "<th>Detected FS</th>" << std::endl;
            out << "</tr>" << std::endl;
            out << "</thead>" << std::endl;

            for (list<TskVolumeInfoRecord>::const_iterator iter = volumeInfoList.begin(); iter != volumeInfoList.end(); iter++) 
            {
                const TskVolumeInfoRecord & vol_info = *iter;
                out << "<tr>" << std::endl;
                out << "<td>" << vol_info.sect_start << "</td>" << std::endl;
                out << "<td>" << (vol_info.sect_start + vol_info.sect_len) - 1 << "</td>" << std::endl;
                out << "<td>" << vol_info.description << "</td>" << std::endl;

                for (list<TskFsInfoRecord>::const_iterator iter2 = fsInfoList.begin(); iter2 != fsInfoList.end(); iter2++)
                {
                    fsInfo = (*iter2); 
                    if(fsInfo.vol_id == vol_info.vol_id)
                    {
                        const char* fsName = tsk_fs_type_toname((TSK_FS_TYPE_ENUM)fsInfo.fs_type);
                        if (!fsName)
                        {
                            out << "<td>Name of file system type is unknown.</td>" << std::endl;
                            LOGERROR("writeReport: Name of file system type is unknown.");
                        }
                        else
                        {
                            out << "<td>" << fsName << "</td>" << std::endl;
                        }
                    }
                }

                out << "</tr>" << std::endl;
            }
            out << "</table>" << std::endl;

            out << "<h2>File Categories</h2>" << std::endl;
            out << "<table class=\"gridtable\">" << std::endl;

            out << "<tr>" << std::endl;
            condition.str("");
            condition << "WHERE files.dir_type = " << TSK_FS_NAME_TYPE_REG 
                      << " AND files.type_id = " << TskImgDB::IMGDB_FILES_TYPE_FS;
            out << "<td><b>File System:</b></td>";
            out << "<td>" << imgdb.getFileCount(condition.str()) << "</td>" << std::endl;
            out << "</tr>" << std::endl;

            out << "<tr>" << std::endl;
            condition.str("");
            condition << "WHERE files.dir_type = " << TSK_FS_NAME_TYPE_REG 
                      << " AND files.type_id = " << TskImgDB::IMGDB_FILES_TYPE_DERIVED;
            out << "<td><b>Derived:</b></td>";
            out << "<td>" << imgdb.getFileCount(condition.str()) << "</td>" << std::endl;
            out << "</tr>" << std::endl;

            out << "<tr>" << std::endl;
            condition.str("");
            condition << "WHERE files.dir_type = " << TSK_FS_NAME_TYPE_REG 
                      << " AND files.type_id = " << TskImgDB::IMGDB_FILES_TYPE_CARVED;
            out << "<td><b>Carved:</b></td>";
            out << "<td>" << imgdb.getFileCount(condition.str()) << "</td>" << std::endl;
            out << "</tr>" << std::endl;

            out << "<tr>" << std::endl;
            condition.str("");
            condition << "WHERE files.dir_type = " << TSK_FS_NAME_TYPE_REG 
                      << " AND files.type_id = " << TskImgDB::IMGDB_FILES_TYPE_UNUSED;
            out << "<td><b>Contiguous Unallocated Sectors:</b></td>";
            out << "<td>" << imgdb.getFileCount(condition.str()) << "</td>" << std::endl;
            out << "</tr>" << std::endl;

            out << "<tr>" << std::endl;
            condition.str("");
            condition << "WHERE files.dir_type = " << TSK_FS_NAME_TYPE_REG;
            out << "<td><b>Total Files:</b></td>";
            out << "<td><b>" << imgdb.getFileCount(condition.str()) << "</b></td>" << std::endl;
            out << "</tr>" << std::endl;

            out << "<tr>" << std::endl;
            out << "</table>" << std::endl;

            std::vector<TskBlackboardArtifact> artifacts = blackboard.getMatchingArtifacts("ORDER BY artifact_type_id");
            std::vector<TskBlackboardArtifact>::iterator it;
            int currentArtType = -1;
            std::vector<int> attrTypeIDs;
            out << "<h2>Blackboard Artifacts</h2>" << std::endl;
            for (it = artifacts.begin(); it != artifacts.end(); it++)
            {
                if (currentArtType != it->getArtifactTypeID())
                {
                    if (currentArtType != -1)
                    {
                        out << "</tbody>" << std::endl << "</table>" << std::endl;
                    }
                    currentArtType = it->getArtifactTypeID();
                    out << "<h3>" << it->getDisplayName() << "</h3>" << std::endl;
                    attrTypeIDs = blackboard.findAttributeTypes(currentArtType);
                    out << "<table class=\"gridtable\">" << std::endl;
                    out << "<thead>" << std::endl;
                    out << "<tr>" << std::endl;
                    out << "<th>File Name</th>" << std::endl;
                    for (size_t i = 0; i < attrTypeIDs.size(); i++)
                    {
                        out << "<th>" << blackboard.attrTypeIDToTypeDisplayName(attrTypeIDs[i]) << "</th>" << std::endl;
                    }
                    out << "</tr>" << std::endl << "</thead>" << std::endl;
                    out << "<tbody>" << std::endl;
                }
                out << "<tr>" << std::endl;
                out << "<td>" << imgdb.getFileName(it->getObjectID()) << "</td>" << std::endl;
                std::vector<TskBlackboardAttribute> attrs = it->getAttributes();

                for (size_t j = 0; j < attrTypeIDs.size(); j++)
                {
                    TskBlackboardAttribute * attr;
                    bool found = false;
                    for (size_t k = 0; k < attrs.size(); k++)
                    {
                        if (attrs[k].getAttributeTypeID() == attrTypeIDs[j])
                        {
                            attr = &attrs[k];
                            found = true;
                            break;
                        }
                    }
                    if (!found)
                    {
                        out << "<td/>" << std::endl;
                    }
                    else
                    {
                        out << "<td>";
                        std::vector<unsigned char> bytes;
                        switch(attr->getValueType())
                        {
                            case TSK_BYTE:
                                bytes = attr->getValueBytes();
                                for(size_t k = 0; k < bytes.size(); k++)
                                    out << bytes[k];
                                out << "</td>" << std::endl;
                                break;

                            case TSK_DOUBLE:
                                out << attr->getValueDouble() << "</td>" << std::endl;
                                break;

                            case TSK_INTEGER:
                                out << attr->getValueInt() << "</td>" << std::endl;
                                break;

                            case TSK_LONG:
                                out << attr->getValueLong() << "</td>" << std::endl;
                                break;

                            case TSK_STRING:
                                std::string encoded = HTMLEncode(attr->getValueString());
                                out << encoded << "</td>" << std::endl;
                                break;
                        }
                    }
                }
                out << "</tr>" << std::endl;
            }
            if (artifacts.size() > 0)
            {
                out << "</tbody>" << std::endl << "</table>" << std::endl;
            }
            out << "</body>" << std::endl;
            out << "</html>" << std::endl;
    }
}

namespace TskSummaryReport
{
    void generateReport(const std::string &reportPath)
    {
        Poco::FileOutputStream out(reportPath, std::ios::out | std::ios::trunc);
        writeReport(out);
    }
}
