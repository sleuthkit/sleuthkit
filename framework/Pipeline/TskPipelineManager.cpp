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
#include "Services/TskSystemProperties.h"
#include "Utilities/TskException.h"
#include "Services/TskServices.h"
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

const std::string TskPipelineManager::FILE_ANALYSIS_PIPELINE = "FileAnalysis";
const std::string TskPipelineManager::REPORTING_PIPELINE = "Report";
const std::string TskPipelineManager::PIPELINE_ELEMENT = "PIPELINE";
const std::string TskPipelineManager::PIPELINE_TYPE = "type";
const std::string TskPipelineManager::DEFAULT_PIPELINE_CONFIG = "pipeline_config.xml";


TskPipelineManager::TskPipelineManager()
{
}

TskPipelineManager::~TskPipelineManager()
{
    // Delete our pipelines
    for (std::vector<TskPipeline *>::iterator it = m_pipelines.begin(); it < m_pipelines.end(); it++)
        delete *it;
}

/**
 * Creates a pipeline object by loading the config file. 
 * Looks for pipeline config file in either the system properties or with the
 * name TskPipelineManager::DEFAULT_PIPELINE_CONFIG in the CONFIG_DIR (as defined
 * in the sytem properties).  
 * @returns Pointer to TskPipeline.  Do not free this. It will be freed by the
 * TskPipelineManager deconstructor. 
 */
TskPipeline * TskPipelineManager::createPipeline(const std::string &pipelineType)
{
    // Get location of Pipeline configuration file.
    std::string pipelineConfig = GetSystemProperty(TskSystemProperties::PIPELINE_CONFIG_FILE);

    // If we haven't been provided with the name of a config file, use the default
    if (pipelineConfig.empty())
        pipelineConfig = TskPipelineManager::DEFAULT_PIPELINE_CONFIG;

    Poco::Path configFile(pipelineConfig);

    // If the path is not absolute then we look for the pipeline
    // config file in the "config" folder.
    if (!configFile.isAbsolute())
    {
        std::string configDir = GetSystemProperty(TskSystemProperties::CONFIG_DIR);
        Poco::Path confDir(configDir);
        confDir.append(configFile);
        configFile = confDir;
    }

    std::ifstream in(configFile.toString().c_str());
    if (!in)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskPipelineManager::createPipeline - Error opening config file: "
            << configFile.toString().c_str() << std::endl;

        LOGERROR(errorMsg.str());
        throw TskException("Error opening pipeline config file.");
    }
    else {
        std::wstringstream msg;
        msg << L"TskPipelineManager::createPipeline -- using config file: " << configFile.toString().c_str();
        LOGINFO(msg.str());
    }

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
            LOGERROR(L"TskPipelineManager::createPipeline - No pipelines found in config file.");

            throw TskException("No pipelines found in config file.");
        }

        TskPipeline * pipeline;
        if (pipelineType == FILE_ANALYSIS_PIPELINE)
            pipeline = new TskFileAnalysisPipeline();
        else if (pipelineType == REPORTING_PIPELINE)
            pipeline = new TskReportPipeline();
        else
            throw TskException("Unsupported pipeline type.");

        m_pipelines.push_back(pipeline);

        for (unsigned long i = 0; i < pipelines->length(); i++)
        {
            Poco::XML::Node * pNode = pipelines->item(i);
            Poco::XML::Element* pElem = dynamic_cast<Poco::XML::Element*>(pNode);

            if (pElem && pElem->getAttribute(TskPipelineManager::PIPELINE_TYPE) == pipelineType)
            {
                // quick sanity check to verify that there is only one pipeline in the config file for this type
                for (unsigned long i2 = i+1; i2 < pipelines->length(); i2++) {
                    Poco::XML::Node * pNode2 = pipelines->item(i2);
                    Poco::XML::Element* pElem2 = dynamic_cast<Poco::XML::Element*>(pNode2);

                    if (pElem2 && pElem2->getAttribute(TskPipelineManager::PIPELINE_TYPE) == pipelineType) {
                        LOGERROR(L"TskPipelineManager::createPipeline: Multiple pipelines of the same type exist");
                        throw TskException ("Error creating pipeline");
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
    catch (Poco::XML::SAXParseException& )
    {
        LOGERROR(L"TskPipelineManager::createPipeline - Error parsing pipeline config file.");
        throw TskException("Error parsing pipeline config file.");
    }
    catch (TskException& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskPipelineManager::createPipeline - Error creating pipeline: "
            << ex.message().c_str() ;
        LOGERROR(errorMsg.str());

        throw TskException("Error creating pipeline.");
    }

    std::wstringstream errorMsg;
    errorMsg << L"TskPipelineManager::createPipeline - Failed to find pipeline for "
        << pipelineType.c_str() ;
    LOGERROR(errorMsg.str());

    throw TskException("Failed to find pipeline for " + pipelineType);
}
