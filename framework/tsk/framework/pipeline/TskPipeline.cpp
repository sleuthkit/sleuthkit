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
 * \file TskPipeline.cpp
 * Contains the implementation for the TskPipeline class.
 */

// Include the class definition first to ensure it does not depend on subsequent includes in this file.
#include "TskPipeline.h"

// TSK Framework includes
#include "TskExecutableModule.h"
#include "TskPluginModule.h"
#include "tsk/framework/file/TskFileManagerImpl.h"
#include "tsk/framework/services/TskServices.h"
#include "tsk/framework/utilities/TskException.h"
#include "tsk/framework/utilities/TskUtilities.h"

// Poco includes
#include "Poco/AutoPtr.h"
#include "Poco/NumberParser.h"
#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/NodeList.h"
#include "Poco/DOM/Document.h"
#include "Poco/UnicodeConverter.h"

// C/C++ library includes
#include <sstream>
#include <assert.h>
#include <memory>

const std::string TskPipeline::MODULE_ELEMENT = "MODULE";
const std::string TskPipeline::MODULE_TYPE_ATTR = "type";
const std::string TskPipeline::MODULE_ORDER_ATTR = "order";
const std::string TskPipeline::MODULE_LOCATION_ATTR = "location";
const std::string TskPipeline::MODULE_ARGS_ATTR = "arguments";
const std::string TskPipeline::MODULE_OUTPUT_ATTR = "output";
const std::string TskPipeline::MODULE_EXECUTABLE_TYPE = "executable";
const std::string TskPipeline::MODULE_PLUGIN_TYPE = "plugin";

TskPipeline::TskPipeline() : m_hasExeModule(false), m_loadDll(true)
{
}

TskPipeline::~TskPipeline()
{
    // Delete modules
    for (std::vector<TskModule*>::iterator it = m_modules.begin(); it != m_modules.end(); it++)
        delete *it;
}

void TskPipeline::validate(const std::string & pipelineConfig)
{
    m_loadDll = false;
    initialize(pipelineConfig);
}

void TskPipeline::initialize(const std::string & pipelineConfig)
{
    if (pipelineConfig.empty())
    {
        throw TskException("TskPipeline::initialize: Pipeline configuration string is empty.");
    }

    try
    {
        Poco::XML::DOMParser parser;
        Poco::AutoPtr<Poco::XML::Document> xmlDoc = parser.parseString(pipelineConfig);

        // Get all Module elements
        Poco::AutoPtr<Poco::XML::NodeList> modules = 
            xmlDoc->getElementsByTagName(TskPipeline::MODULE_ELEMENT);

        if (modules->length() == 0)
        {
            LOGWARN(L"TskPipeline::initialize - No modules found in config file.");
            return;
        }

        // Size our list based on the number of modules
        m_modules.resize(modules->length());

        // Iterate through the module elements, make sure they are increasing order
        // we now allow for gaps to make it easier to comment things out.
        int prevOrder = -1;
        for (unsigned int i = 0; i < modules->length(); i++)
        {
            Poco::XML::Node * pNode = modules->item(i);
            Poco::XML::Element* pElem = dynamic_cast<Poco::XML::Element*>(pNode);
            Poco::XML::XMLString orderStr = pElem->getAttribute(TskPipeline::MODULE_ORDER_ATTR);
            if (orderStr == "") {
                throw TskException("TskPipeline::initialize: Module order missing.");
            }
            int order;
            try 
            {
                order = Poco::NumberParser::parse(orderStr);
            } catch (Poco::SyntaxException ex) 
            {
                std::stringstream msg;
                msg << "TskPipeline::initialize - Module order must a decimal number. Got " << orderStr.c_str();
                throw TskException(msg.str());
            }
            if (order <= prevOrder) 
            {
                std::stringstream msg;
                msg << "TskPipeline::initialize - Expecting order bigger than " << prevOrder << ", got " << order;
                throw TskException(msg.str());
            }
            prevOrder = order;
        }

        // Iterate through the module elements creating a new Module for each one
        m_modules.clear();
        for (unsigned int i = 0; i < modules->length(); i++)
        {
            Poco::XML::Node * pNode = modules->item(i);
            Poco::XML::Element* pElem = dynamic_cast<Poco::XML::Element*>(pNode);

            if (!pElem)
                continue;

            // Create a new module
            TskModule * pModule = createModule(pElem);

            if (pModule == NULL)
            {
                throw TskException("TskPipeline::initialize - Module creation failed.");
            }

            if (m_loadDll) 
            {
                TskImgDB& imgDB = TskServices::Instance().getImgDB();

                // Insert into Modules table
                int moduleId = 0;
                if (imgDB.addModule(pModule->getName(), pModule->getDescription(), moduleId)) 
                {
                    std::stringstream errorMsg;
                    errorMsg << "TskPipeline::initialize - Failed to insert into Modules table. "  
                             << " module name=" << pModule->getName() ;
                    throw TskException(errorMsg.str());
                } 
                else 
                {
                    pModule->setModuleId(moduleId);
                    m_moduleNames.insert(std::make_pair(moduleId, pModule->getName()));
                    m_moduleExecTimes.insert(std::make_pair(moduleId, Poco::Timespan()));
                }
                bool duplicate = false;
                for (std::vector<TskModule*>::iterator it = m_modules.begin(); it != m_modules.end(); it++) {
                    if ((*it)->getModuleId() == pModule->getModuleId()) {
                        duplicate = true;
                        std::stringstream msg;
                        msg << "TskPipeline::initialize - " << pModule->getName() << " is a duplicate module. " <<
                            "The duplicate will not be added to the pipeline";
                        throw TskException(msg.str());
                    }
                }
                if (!duplicate)
                    m_modules.push_back(pModule);
            }
        }
    }
    // rethrow this, otherwise it is caught by std::exception and we lose the detail.
    catch (TskException& ex) {
        throw(ex);
    }
    catch (std::exception& ex)
    {
        std::stringstream errorMsg;
        errorMsg << "TskPipeline::initialize - Pipeline initialization failed: " <<ex.what() ;
        throw TskException(errorMsg.str());
    }
}

TskModule * TskPipeline::createModule(Poco::XML::Element *pElem)
{
    if (!pElem)
    {
        LOGERROR(L"TskPipeline::createModule - Passed NULL Element.");
        return NULL;
    }

    try
    {
        if (pElem->getAttribute(TskPipeline::MODULE_TYPE_ATTR) == MODULE_EXECUTABLE_TYPE)
        {
            // Use auto_ptr to ensure that module will be deleted if there 
            // are exceptions.
            std::auto_ptr<TskExecutableModule> pModule(new TskExecutableModule());
            std::string location(pElem->getAttribute(TskPipeline::MODULE_LOCATION_ATTR));
            pModule->setPath(location);
            //pModule->setPath(pElem->getAttribute(TskPipeline::MODULE_LOCATION_ATTR));
            pModule->setArguments(pElem->getAttribute(TskPipeline::MODULE_ARGS_ATTR));
            pModule->setOutput(pElem->getAttribute(TskPipeline::MODULE_OUTPUT_ATTR));

            m_hasExeModule = true;

            // The module was successfully created so we no longer need the
            // auto_ptr to manage it.
            return pModule.release();
        }
        else if (pElem->getAttribute(TskPipeline::MODULE_TYPE_ATTR) == MODULE_PLUGIN_TYPE)
        {
            std::auto_ptr<TskPluginModule> pModule(createPluginModule());
            pModule->setPath(pElem->getAttribute(TskPipeline::MODULE_LOCATION_ATTR));
            pModule->setArguments(pElem->getAttribute(TskPipeline::MODULE_ARGS_ATTR));
            pModule->checkInterface();

            // Initialize the module.
            if (m_loadDll)
            {
                if (pModule->initialize() != TskModule::OK)
                {
                    return NULL;
                }
            }

            // The module was successfully created and initialized so we no longer
            // need the auto_ptr to manage it.
            return pModule.release();
        }
        else
        {
            std::wstringstream errorMsg;
            errorMsg << "TskPipeline::createModule - Unrecognized module type : "
                << pElem->getAttribute(TskPipeline::MODULE_TYPE_ATTR).c_str();
            LOGERROR(errorMsg.str());

            return NULL;
        }
    }
    catch (TskException& ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskPipeline::createModule - Module creation failed: " << pElem->getAttribute(TskPipeline::MODULE_LOCATION_ATTR).c_str() << L" ("<< ex.message().c_str()<< L")";
        LOGERROR(errorMsg.str());
        return NULL;
    }
    catch (std::exception & ex)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskPipeline::createModule - Module creation failed: " << pElem->getAttribute(TskPipeline::MODULE_LOCATION_ATTR).c_str() << L" ("<< ex.what() << L")";
        LOGERROR(errorMsg.str());
        return NULL;
    }
    catch (...)
    {
        std::wstringstream errorMsg;
        errorMsg << L"TskPipeline::createModule - Unnkown exception : " << pElem->getAttribute(TskPipeline::MODULE_LOCATION_ATTR).c_str() ;
        LOGERROR(errorMsg.str());
        return NULL;
    }

}

void TskPipeline::logModuleExecutionTimes() const
{
    for (std::map<int, Poco::Timespan>::const_iterator it = m_moduleExecTimes.begin(); it != m_moduleExecTimes.end(); ++it)
    {
        assert(m_moduleNames.find(it->first) != m_moduleNames.end());
        std::stringstream msg;
        msg << "TskPipeline::logModuleExecutionTimes : "  << m_moduleNames.find(it->first)->second << " total execution time was "
        << it->second.days() << ":" << it->second.hours() << ":" << it->second.minutes() << ":" << it->second.seconds() << ":" << it->second.milliseconds()
        << " (days:hrs:mins:secs:ms)";
        LOGINFO(msg.str());
    }
}

bool TskPipeline::excludeFile(const TskFile* file)
{
    if (file == NULL)
    {
        LOGERROR(L"TskPipeline::excludeFile - Passed NULL file pointer.");
        throw TskNullPointerException();
    }

    // Exclude directories and Sleuthkit "virtual" files from analysis.
    if (file->isDirectory() || file->isVirtual())
        return true;

    return false;
}

void TskPipeline::updateModuleExecutionTime(int moduleId, const Poco::Timespan::TimeDiff &executionTime)
{
    std::map<int, Poco::Timespan>::iterator it = m_moduleExecTimes.find(moduleId);
    if (it != m_moduleExecTimes.end())
    {
        it->second += executionTime;
    }
    else
    {
        std::stringstream msg;
        msg << "TskPipeline::updateModuleExecutionTime : unknown moduleId " << moduleId;
        LOGERROR(msg.str());
    }
}
