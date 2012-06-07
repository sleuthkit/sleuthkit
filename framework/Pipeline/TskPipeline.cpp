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

// System includes
#include <sstream>

// Framework includes
#include "TskPipeline.h"
#include "TskExecutableModule.h"
#include "TskPluginModule.h"
#include "File/TskFileManagerImpl.h"
#include "Services/TskServices.h"
#include "Utilities/TskException.h"
#include "Utilities/TskUtilities.h"

// Poco includes
#include "Poco/AutoPtr.h"
#include "Poco/NumberParser.h"
#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/Nodelist.h"
#include "Poco/DOM/Document.h"

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

/**
 * Validate a Pipeline based on the given XML configuration string. 
 * @param pipelineConfig String of config file for the specific type of pipeline. 
 * @throws TskException in case of error.
 */
void TskPipeline::validate(const std::string & pipelineConfig)
{
    m_loadDll = false;
    initialize(pipelineConfig);
}

/**
 * Parses the XML config file.  Modules are loaded if m_loadDll is set to true. 
 * @param pipelineConfig String of a config file for the specific type of pipeline.
 * @throws TskException in case of error.
 */
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

            // Put the new module into the list if the slot isn't already taken.
            int order = Poco::NumberParser::parse(pElem->getAttribute(TskPipeline::MODULE_ORDER_ATTR));
            

            if (m_loadDll) {
                TskImgDB& imgDB = TskServices::Instance().getImgDB();

                // Insert into Modules table
                int moduleId = 0;
                if (imgDB.addModule(pModule->getName(), "", moduleId)) {
                    std::stringstream errorMsg;
                    errorMsg << "TskPipeline::initialize - Failed to insert into Modules table. "  
                             << " module name=" << pModule->getName() ;
                    throw TskException(errorMsg.str());
                } else {
                    pModule->setModuleId(moduleId);
                }
            }
            m_modules.push_back(pModule);
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

/**
 * Creates a module of the type specified in the XML element.
 * @param pElem element type from XML file. 
 * @returns NULL on error 
 */
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
            pModule->setPath(pElem->getAttribute(TskPipeline::MODULE_LOCATION_ATTR));
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

            // Initialize the module. Will throw an exception on failure.
            if (m_loadDll)
                pModule->initialize();

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

/**
 * Determine whether a particular file should be processed.
 * @returns true if file should be excluded, false otherwise
 */
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
