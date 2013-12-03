/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskPipelineManager.cpp
 * Contains the implementation for the TskPipelineManager class.
 */

// System includes
#include <sstream>
#include <fstream>

// Framework includes
#include "TskPipelineManager.h"
#include "tsk/framework/services/TskSystemProperties.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/services/TskServices.h"
#include "TskFileAnalysisPipeline.h"
#include "TskReportPipeline.h"

// Poco includes
#include "Poco/AutoPtr.h"
#include "Poco/Path.h"
#include "Poco/UnicodeConverter.h"
#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/Document.h"
#include "Poco/DOM/NodeList.h"
#include "Poco/DOM/NodeIterator.h"
#include "Poco/DOM/DOMWriter.h"
#include "Poco/SAX/InputSource.h"
#include "Poco/SAX/SAXException.h"

const std::string TskPipelineManager::FILE_ANALYSIS_PIPELINE_STR = "FileAnalysis";
const std::string TskPipelineManager::POST_PROCESSING_PIPELINE_STR = "PostProcessing";
const std::string TskPipelineManager::REPORTING_PIPELINE_STR = "Report";
const std::string TskPipelineManager::PIPELINE_ELEMENT = "PIPELINE";
const std::string TskPipelineManager::PIPELINE_TYPE_ATTRIBUTE = "type";
const std::string TskPipelineManager::PIPELINE_NAME_ATTRIBUTE = "name";

TskPipelineManager::TskPipelineManager()
{
}

TskPipelineManager::~TskPipelineManager()
{
    // Delete our pipelines
    for (std::vector<TskPipeline *>::iterator it = m_pipelines.begin(); it < m_pipelines.end(); it++)
        delete *it;
}

TskPipeline * TskPipelineManager::createPipeline(const PIPELINE_TYPE type, const std::string& name)
{
    std::string funcName("TskPipelineManager::createPipeline");

    std::string pipelineConfigFilePath = GetSystemProperty(TskSystemProperties::PIPELINE_CONFIG_FILE);
    std::ifstream in(pipelineConfigFilePath.c_str());
    if (!in)
    {
        throw TskException("Error opening pipeline config file.");
    }
    else 
    {
        std::stringstream msg;
        msg << funcName << " : Using config file '" << pipelineConfigFilePath;
        LOGINFO(msg.str());
    }

    std::string pipelineType = pipelineTypeToString(type);

    try
    {
        Poco::XML::InputSource src(in);

        // Parse the XML into a Poco::XML::Document
        Poco::XML::DOMParser parser;
        Poco::AutoPtr<Poco::XML::Document> xmlDoc = parser.parse(&src);

        // Locate the PIPELINE element that matches pipelineType
        Poco::AutoPtr<Poco::XML::NodeList> pipelines = 
            xmlDoc->getElementsByTagName(TskPipelineManager::PIPELINE_ELEMENT);

        if (pipelines->length() == 0)
        {
            throw TskException("No pipelines found in config file.");
        }

        TskPipeline * pipeline;
        if (type == FILE_ANALYSIS_PIPELINE)
            pipeline = new TskFileAnalysisPipeline();
        else if (type == POST_PROCESSING_PIPELINE)
            pipeline = new TskReportPipeline();
        else
            throw TskException("Unsupported pipeline type.");

        m_pipelines.push_back(pipeline);

        for (unsigned long i = 0; i < pipelines->length(); i++)
        {
            Poco::XML::Node * pNode = pipelines->item(i);
            Poco::XML::Element* pElem = dynamic_cast<Poco::XML::Element*>(pNode);

            if (pElem)
            {
                std::string xmlPipelineType = pElem->getAttribute(TskPipelineManager::PIPELINE_TYPE_ATTRIBUTE);
                std::string xmlPipelineName = pElem->getAttribute(TskPipelineManager::PIPELINE_NAME_ATTRIBUTE);

                // The following conditions are required because we want to be able to use 
                // "PostProcessing" and "Report" to be used interchangeably (at least for the moment).
                // Note that the sanity check below will not catch the case where there are both
                // "PostProcessing" and "Report" pipelines in the configuration file.
                if (xmlPipelineName == name && (xmlPipelineType == pipelineType) ||
                    (pipelineType == REPORTING_PIPELINE_STR && xmlPipelineType == POST_PROCESSING_PIPELINE_STR) ||
                    (pipelineType == POST_PROCESSING_PIPELINE_STR && xmlPipelineType == REPORTING_PIPELINE_STR))
                {
                    // quick sanity check to verify that there is only one pipeline in the config file for this type and name
                    for (unsigned long i2 = i+1; i2 < pipelines->length(); i2++) {
                        Poco::XML::Node * pNode2 = pipelines->item(i2);
                        Poco::XML::Element* pElem2 = dynamic_cast<Poco::XML::Element*>(pNode2);

                        if (pElem2 && 
                            pElem2->getAttribute(TskPipelineManager::PIPELINE_TYPE_ATTRIBUTE) == pipelineType &&
                            pElem2->getAttribute(TskPipelineManager::PIPELINE_NAME_ATTRIBUTE) == name) 
                        {
                            std::stringstream exMsg;
                            exMsg << "Multiple pipelines found with the same type (" << pipelineType
                                << ") and name (" << name << ")";
                            throw TskException (exMsg.str());
                        }
                    }
                    // We found the right pipeline so initialize it.
                    Poco::XML::DOMWriter writer;
                    std::ostringstream pipelineXml;
                    writer.writeNode(pipelineXml, pNode);

                    pipeline->initialize(pipelineXml.str());

                    return pipeline;
                }
            }
        }
    }
    catch (Poco::XML::SAXParseException& )
    {
        throw TskException("Error parsing pipeline config file.");
    }
    catch (TskException& ex)
    {
        throw ex;
    }

    std::stringstream errorMsg;
    errorMsg << "Failed to find " << pipelineType << " pipeline";
    if (!name.empty())
        errorMsg << " with name " << name;

    throw TskException(errorMsg.str());
}

/**
 * Creates a pipeline object by reading the pipeline config file specified as
 * a system property. 
 * @returns Pointer to TskPipeline.  Do not free this. It will be freed by the
 * TskPipelineManager destructor. 
 */
TskPipeline * TskPipelineManager::createPipeline(const std::string &pipelineType)
{
    if (pipelineType == REPORTING_PIPELINE_STR || pipelineType == POST_PROCESSING_PIPELINE_STR)
        return createPipeline(TskPipelineManager::POST_PROCESSING_PIPELINE);
    else if (pipelineType == FILE_ANALYSIS_PIPELINE_STR)
        return createPipeline(TskPipelineManager::FILE_ANALYSIS_PIPELINE);
    else
    {
        std::stringstream exMsg;
        exMsg << "TskPipelineManager::createPipeline : Unsupported pipeline type : " << pipelineType;
        throw TskException(exMsg.str());
    }
}

std::string TskPipelineManager::pipelineTypeToString(const PIPELINE_TYPE type)
{
    switch (type)
    {
    case FILE_ANALYSIS_PIPELINE:
        return FILE_ANALYSIS_PIPELINE_STR;
    case POST_PROCESSING_PIPELINE:
        return POST_PROCESSING_PIPELINE_STR;
    default:
        return "Unknown pipeline type";
    }
}
