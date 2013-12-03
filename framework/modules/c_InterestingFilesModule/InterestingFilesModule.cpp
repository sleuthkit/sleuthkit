/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file InterestingFilesModule.cpp
 * Contains the implementation of a post-processing/reporting module that
 * looks for files matching interesting file set criteria specified in a 
 * module configuration file. The module posts its findings to the blackboard. 
 */

// TSK Framework includes
#include "tsk/framework/utilities/TskModuleDev.h"

// Poco includes
#include "Poco/String.h"
#include "Poco/AutoPtr.h"
#include "Poco/Path.h"
#include "Poco/File.h"
#include "Poco/NumberParser.h"
#include "Poco/DOM/DOMParser.h"
#include "Poco/DOM/Document.h"
#include "Poco/DOM/NodeList.h"
#include "Poco/DOM/NamedNodeMap.h"
#include "Poco/SAX/InputSource.h"
#include "Poco/SAX/SAXException.h"

// System includes
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <fstream>

namespace
{
    const char *MODULE_NAME = "tskInterestingFilesModule";
    const char *MODULE_DESCRIPTION = "Looks for files matching criteria specified in a module configuration file";
    const char *MODULE_VERSION = "1.0.0";
    const std::string DEFAULT_CONFIG_FILE_NAME = "interesting_files.xml";
    const std::string INTERESTING_FILE_SET_ELEMENT_TAG = "INTERESTING_FILE_SET"; 
    const std::string NAME_ATTRIBUTE = "name";
    const std::string DESCRIPTION_ATTRIBUTE_TAG = "description";
    const std::string IGNORE_KNOWN_TAG = "ignoreKnown";
    const std::string NAME_ELEMENT_TAG = "NAME";
    const std::string EXTENSION_ELEMENT_TAG = "EXTENSION";
    const std::string PATH_FILTER_ATTRIBUTE = "pathFilter";
    const std::string TYPE_FILTER_ATTRIBUTE = "typeFilter";
    const std::string FILE_TYPE_FILTER_VALUE = "file";
    const std::string DIR_TYPE_FILTER_VALUE = "dir";

    std::string configFilePath;

    // The following variables track whether we should ignore known
    // files (and what type of known files to ignore) at a global 
    // level. These settings can be overridden on an individual
    // file set.

    // Whether we should ignore known files.
    bool ignoreKnown = false;

    // What type of known files to ignore.
    TskImgDB::KNOWN_STATUS knownType = TskImgDB::IMGDB_FILES_KNOWN;

    /** 
     * An interesting files set is defined by a set name, a set description, 
     * and one or more SQL WHERE clauses that specify what files belong to the
     * set.
     */
    struct InterestingFilesSet
    {
        InterestingFilesSet() 
            : name(""), description(""), ignoreKnown(false), knownType(TskImgDB::IMGDB_FILES_KNOWN) {}
        std::string name;
        std::string description;
        bool ignoreKnown;
        TskImgDB::KNOWN_STATUS knownType;
        vector<std::string> conditions;
    };

    /**
     * Interesting file set definitions are read from a configuration file in 
     * the initialize() module API and the file queries are executed in the 
     * report() module API. The following vector stores the search objects 
     * between calls to intitialize() and report(). 
     */
    std::vector<InterestingFilesSet> fileSets;

    /** 
     * Looks for glob wildcards in a string.
     *
     * @param stringToCheck The string to be checked.
     * @return True if any glob wildcards where found.
     */
    bool hasGlobWildcards(const std::string &stringToCheck)
    {
        return stringToCheck.find("*") != std::string::npos;
    }

    std::string EscapeWildcard(const std::string &s, char escChar) 
    {
        std::string newS;
        for (size_t i = 0; i < s.length(); i++) {
            char c = s[i];
            if (c == '_' || c == '%' || c == escChar) {
                newS += escChar;
            }
            newS += c;
        }
        return newS;
    }

    /** 
     * Converts glob wildcards in a string to SQL wildcards.
     *
     * @param stringToChange The string to be changed.
     */
    void convertGlobWildcardsToSQLWildcards(std::string &stringToChange)
    {
        // Escape all SQL wildcards chars and escape chars that happen to be in the input string.
        stringToChange = EscapeWildcard(stringToChange, '#');

        // Convert the glob wildcard chars to SQL wildcard chars.
        Poco::replaceInPlace(stringToChange, "*", "%");
    }

    /**
     * Verifies that the given attribute value is a valid integer value
     * for a known type and converts the value to its corresponding enum.
     */
    TskImgDB::KNOWN_STATUS parseKnownType(const std::string& attributeValue)
    {
        const std::string MSG_PREFIX(MODULE_NAME + std::string("::parseKnownType : "));

        int knownType = Poco::NumberParser::parse(attributeValue);
        if (knownType > TskImgDB::IMGDB_FILES_UNKNOWN || knownType < TskImgDB::IMGDB_FILES_KNOWN)
        {
            std::ostringstream msg;
            msg << MSG_PREFIX << "Invalid value for ignoreKnown.";
            throw TskException(msg.str());
        }

        return static_cast<TskImgDB::KNOWN_STATUS>(knownType);
    }

    /** 
     * Adds optional file type (file, directory) and path substring filters to 
     * an SQL WHERE clause for a file search condition.
     *
     * @param conditionDefinition A file name or extension condition XML 
     * element.
     * @param conditionBuilder A string stream to which to append the filters.
     */
    void addPathAndTypeFilterOptions(const Poco::XML::Node *conditionDefinition, std::stringstream &conditionBuilder)
    {
        const std::string MSG_PREFIX = "InterestingFilesModule::compileExtensionSearchCondition : ";

        if (conditionDefinition->hasAttributes())
        {
            // Look for pathFilter and typeFilter attributes.
            Poco::AutoPtr<Poco::XML::NamedNodeMap> attributes = conditionDefinition->attributes(); 
            for (unsigned long i = 0; i < attributes->length(); ++i)
            {
                Poco::XML::Node *attribute = attributes->item(i);
                const std::string& attributeName = Poco::XML::fromXMLString(attribute->nodeName());
                std::string attributeValue(Poco::XML::fromXMLString(attribute->nodeValue()));
                if (attributeName == PATH_FILTER_ATTRIBUTE)
                {        
                    if (!attributeValue.empty())
                    {
                        // File must include a specified substring somewhere in its path.
                        convertGlobWildcardsToSQLWildcards(attributeValue);
                        conditionBuilder << " AND UPPER(full_path) LIKE UPPER('%" + attributeValue + "%') ESCAPE '#'";
                    }
                    else
                    {
                        std::ostringstream msg;
                        msg << MSG_PREFIX << Poco::XML::fromXMLString(conditionDefinition->nodeName()) << " element has empty " << PATH_FILTER_ATTRIBUTE << " attribute"; 
                        throw TskException(msg.str());
                    }
                }
                else if (attributeName == TYPE_FILTER_ATTRIBUTE)
                {
                    if (!attributeValue.empty())
                    {
                        if (attributeValue == FILE_TYPE_FILTER_VALUE)
                        {
                            // File must be a regular file.
                            conditionBuilder << " AND meta_type = " << TSK_FS_META_TYPE_REG;
                        }
                        else if (attributeValue == DIR_TYPE_FILTER_VALUE)
                        {
                            // File must be a directory.
                            conditionBuilder << " AND meta_type = " << TSK_FS_META_TYPE_DIR;
                        }
                        else
                        {
                            std::ostringstream msg;
                            msg << MSG_PREFIX << Poco::XML::fromXMLString(conditionDefinition->nodeName()) << " element has unrecognized " << TYPE_FILTER_ATTRIBUTE << " attribute value: " << attributeValue; 
                            throw TskException(msg.str());
                        }
                    }
                    else
                    {
                        std::ostringstream msg;
                        msg << MSG_PREFIX << Poco::XML::fromXMLString(conditionDefinition->nodeName()) << " element has empty " << TYPE_FILTER_ATTRIBUTE << " attribute"; 
                        throw TskException(msg.str());
                    }
                }
                else
                {
                    std::stringstream msg;
                    msg << MSG_PREFIX << Poco::XML::fromXMLString(conditionDefinition->nodeName()) << " element has unrecognized " << attributeName << " attribute"; 
                    throw TskException(msg.str());
                }
            }
        }
    }

    /**
      * Creates an SQL condition to find files based on file name.
      *
      * @param conditionDefinition A file name condition XML element.
      * @return The constructed SQL condition.
      */
    std::string compileFileNameSearchCondition(const Poco::XML::Node *conditionDefinition)
    {
        const std::string MSG_PREFIX = "InterestingFilesModule::compileFileNameSearchCondition : ";

        std::string name(Poco::XML::fromXMLString(conditionDefinition->innerText()));
        if (name.empty())
        {
            std::ostringstream msg;
            msg << MSG_PREFIX << "empty " << NAME_ELEMENT_TAG << " element"; 
            throw TskException(msg.str());
        }

        std::stringstream conditionBuilder;

        if (hasGlobWildcards(name))
        {
            convertGlobWildcardsToSQLWildcards(name);
            conditionBuilder << "UPPER(name) LIKE UPPER(" << TskServices::Instance().getImgDB().quote(name) << ") ESCAPE '#' ";
        }
        else
        {
            conditionBuilder << "UPPER(name) = UPPER(" +  TskServices::Instance().getImgDB().quote(name) + ")";
        }

        addPathAndTypeFilterOptions(conditionDefinition, conditionBuilder);

        return conditionBuilder.str();
    }

    /**
      * Creates an SQL condition to find files based on extension.
      *
      * @param conditionDefinition A file extension condition XML element.
      * @returns The SQL condition.
      */
    std::string compileExtensionSearchCondition(const Poco::XML::Node *conditionDefinition)
    {
        const std::string MSG_PREFIX = "InterestingFilesModule::compileExtensionSearchCondition : ";

        std::string extension(Poco::XML::fromXMLString(conditionDefinition->innerText()));
        if (extension.empty())
        {
            std::ostringstream msg;
            msg << MSG_PREFIX << "empty " << EXTENSION_ELEMENT_TAG << " element"; 
            throw TskException(msg.str());
        }

        // Supply the leading dot, if omitted.
        if (extension[0] != '.')
        {
            extension.insert(0, ".");
        }

        convertGlobWildcardsToSQLWildcards(extension);
        
        // Extension searches must always have an initial SQL zero to many chars wildcard.
        // @@@ TODO: In combination with glob wildcards this may create some unxepected matches.
        // For example, ".htm*" will become "%.htm%" which will match "file.htm.txt" and the like.
        std::stringstream conditionBuilder;
        conditionBuilder << "UPPER(name) LIKE UPPER('%" << extension << "') ESCAPE '#' ";

        addPathAndTypeFilterOptions(conditionDefinition, conditionBuilder);

        return conditionBuilder.str();
    }

    /** 
     * Creates an InterestingFilesSet object from an an interesting files 
     * set definition. 
     *
     * @param fileSetDefinition An interesting file set definition XML element.
     */
    void compileInterestingFilesSet(const Poco::XML::Node *fileSetDefinition)
    {
        // Create a counter for use in generating default interesting file set names.
        static unsigned long defaultSetNumber = 1;

        // Keep track of unique file set names.
        static std::set<std::string> setNames;

        // Determine the name and description of the file set. Every file set must be named, but the description is optional.
        // A default name is provided if omitted, so the parsing that follows logs warnings if unexpected attributes or values are parsed.
        const std::string MSG_PREFIX = "InterestingFilesModule::compileInterestingFilesSet : ";
        InterestingFilesSet fileSet;
        if (fileSetDefinition->hasAttributes())
        {
            Poco::AutoPtr<Poco::XML::NamedNodeMap> attributes = fileSetDefinition->attributes(); 
            for (unsigned long i = 0; i < attributes->length(); ++i)
            {
                Poco::XML::Node *attribute = attributes->item(i);
                const std::string &attributeName = Poco::XML::fromXMLString(attribute->nodeName());                
                const std::string &attributeValue = Poco::XML::fromXMLString(attribute->nodeValue());
                if (!attributeValue.empty())
                {
                    if (attributeName == NAME_ATTRIBUTE)
                    {        
                        if (!attributeValue.empty())
                        {
                            fileSet.name = attributeValue;
                        }
                        else
                        {
                            std::ostringstream msg;
                            msg << MSG_PREFIX << "ignored " << INTERESTING_FILE_SET_ELEMENT_TAG << "'" << NAME_ATTRIBUTE << "' attribute without a value"; 
                            LOGWARN(msg.str());
                        }
                    }
                    else if (attributeName == DESCRIPTION_ATTRIBUTE_TAG)
                    {
                        if (!attributeValue.empty())
                        {
                            fileSet.description = attributeValue;
                        }
                        else
                        {
                            std::ostringstream msg;
                            msg << MSG_PREFIX << "ignored " << INTERESTING_FILE_SET_ELEMENT_TAG << "'" << DESCRIPTION_ATTRIBUTE_TAG << "' attribute without a value"; 
                            LOGWARN(msg.str());
                        }
                    }
                    else if (attributeName == IGNORE_KNOWN_TAG)
                    {
                        if (!attributeValue.empty())
                        {
                            fileSet.knownType = parseKnownType(attributeValue);
                            fileSet.ignoreKnown = true;
                        }
                        else
                        {
                            std::ostringstream msg;
                            msg << MSG_PREFIX << "ignored " << INTERESTING_FILE_SET_ELEMENT_TAG << "'" << IGNORE_KNOWN_TAG << "' attribute without a value"; 
                            LOGWARN(msg.str());
                        }
                    }
                    else
                    {
                        std::ostringstream msg;
                        msg << MSG_PREFIX << "ignored unrecognized " << INTERESTING_FILE_SET_ELEMENT_TAG << "'" << attributeName << "' attribute"; 
                        LOGWARN(msg.str());
                    }
                }
            }
        }

        if (fileSet.name.empty())
        {
            // Supply a default name.
            std::stringstream nameBuilder;
            nameBuilder << "Unnamed_" << defaultSetNumber++;
            fileSet.name = nameBuilder.str();
        }

        // The file set name cannot contain a path character since it may be used later
        // as a folder name by a save interesting files module.
        if (fileSet.name.find_first_of("<>:\"/\\|?*") != std::string::npos)
        {
            std::ostringstream msg;
            msg << MSG_PREFIX << INTERESTING_FILE_SET_ELEMENT_TAG << " element " << NAME_ATTRIBUTE << " attribute value '" << fileSet.name << "' contains file path character";
            throw TskException(msg.str());
        }

        // The file set name cannot be shorthand for the a current directory or parent directory since it may be used later
        // as a folder name by a save interesting files module.
        if (fileSet.name == (".") || fileSet.name == (".."))
        {
            std::ostringstream msg;
            msg << MSG_PREFIX << INTERESTING_FILE_SET_ELEMENT_TAG << " element " << NAME_ATTRIBUTE << " attribute value '" << fileSet.name << "' is directory alias";
            throw TskException(msg.str());
        }

        // Every file set must be uniquely named since it may be used later as a folder name by a save interesting files module.
        if (setNames.count(fileSet.name) != 0)
        {
            std::ostringstream msg;
            msg << MSG_PREFIX << "duplicate " << INTERESTING_FILE_SET_ELEMENT_TAG << " element " << NAME_ATTRIBUTE << " attribute value '" << fileSet.name << "'";
            throw TskException(msg.str());
        }

        std::string conditionBase;

        // If we want to ignore known files either on an individual file set
        // or globally we need to join with the file_hashes table.
        if (fileSet.ignoreKnown || ignoreKnown)
            conditionBase = " JOIN file_hashes ON (files.file_id = file_hashes.file_id) WHERE ";
        else
            conditionBase = " WHERE ";

        // Get the search conditions.
        Poco::AutoPtr<Poco::XML::NodeList>conditionDefinitions = fileSetDefinition->childNodes();
        for (unsigned long i = 0; i < conditionDefinitions->length(); ++i)
        {
            Poco::XML::Node *conditionDefinition = conditionDefinitions->item(i);
            if (conditionDefinition->nodeType() == Poco::XML::Node::ELEMENT_NODE) 
            {
                const std::string &conditionType = Poco::XML::fromXMLString(conditionDefinition->nodeName());
                std::stringstream conditionBuilder;

                conditionBuilder << conditionBase;

                if (conditionType == NAME_ELEMENT_TAG)
                {
                    conditionBuilder << compileFileNameSearchCondition(conditionDefinition);
                }
                else if (conditionType == EXTENSION_ELEMENT_TAG)
                {
                    conditionBuilder << compileExtensionSearchCondition(conditionDefinition);
                }
                else
                {
                    std::ostringstream msg;
                    msg << MSG_PREFIX << "unrecognized " << INTERESTING_FILE_SET_ELEMENT_TAG << " child element '" << conditionType << "'"; 
                    throw TskException(msg.str());
                }

                if (fileSet.ignoreKnown)
                    conditionBuilder << " AND file_hashes.known != " << fileSet.knownType;
                else if (ignoreKnown)
                    conditionBuilder << " AND file_hashes.known != " << knownType;

                conditionBuilder << " ORDER BY files.file_id";
                fileSet.conditions.push_back(conditionBuilder.str());
            }

        }

        if (!fileSet.conditions.empty())
        {
            fileSets.push_back(fileSet);
        }
        else
        {
            std::ostringstream msg;
            msg << MSG_PREFIX << "empty " << INTERESTING_FILE_SET_ELEMENT_TAG << " element '" << fileSet.name << "'"; 
            //throw TskException(msg.str());
        }
    }
}

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module.
     */
    TSK_MODULE_EXPORT const char *name()
    {
        return MODULE_NAME;
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module.
     */
    TSK_MODULE_EXPORT const char *description()
    {
        return MODULE_DESCRIPTION;
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module.
     */
    TSK_MODULE_EXPORT const char *version()
    {
        return MODULE_VERSION;
    }

    /**
     * Module initialization function. The initialization arguments string should
     * provide the path of a module configuration file that defines what files 
     * are interesting. If the empty string is passed to this function, the module
     * assumes a default config file is present in the output directory.
     *
     * @param args Path of the configuration file that defines what files are 
     * interesting, may be set to the empty string.
     * @return TskModule::OK on success, TskModule::FAIL otherwise. 
     */
    TSK_MODULE_EXPORT TskModule::Status initialize(const char* arguments)
    {
        TskModule::Status status = TskModule::OK;

        const std::string MSG_PREFIX = "InterestingFilesModule::initialize : ";
        try
        {
            // Make sure the file sets are cleared in case initialize() is called more than once.
            fileSets.clear();

            configFilePath.assign(arguments);
            if (configFilePath.empty())
            {
                // Use the default config file path.
                Poco::Path configurationFilePath(Poco::Path::forDirectory(GetSystemProperty(TskSystemProperties::MODULE_CONFIG_DIR)));
                configurationFilePath.pushDirectory(MODULE_NAME);
                configurationFilePath.setFileName(DEFAULT_CONFIG_FILE_NAME);
                configFilePath = configurationFilePath.toString();
            }

            // Compile the contents of the config file into interesting file set definitions.
            Poco::File configFile = Poco::File(configFilePath);
            if (configFile.exists())
            {
                std::ifstream configStream(configFile.path().c_str());
                if (configStream)
                {
                    Poco::XML::InputSource inputSource(configStream);
                    Poco::AutoPtr<Poco::XML::Document> configDoc = Poco::XML::DOMParser().parse(&inputSource);

                    Poco::XML::Element * rootElement = configDoc->documentElement();
                    if (rootElement == NULL)
                    {
                        std::ostringstream msg;
                        msg << MSG_PREFIX << "Root element of config file is NULL.";
                        throw TskException(msg.str());
                    }

                    const std::string& ignoreKnownValue = Poco::XML::fromXMLString(rootElement->getAttribute(IGNORE_KNOWN_TAG));

                    if (!ignoreKnownValue.empty())
                    {
                        knownType = parseKnownType(ignoreKnownValue);
                        ignoreKnown = true;
                    }

                    Poco::AutoPtr<Poco::XML::NodeList> fileSetDefinitions = configDoc->getElementsByTagName(INTERESTING_FILE_SET_ELEMENT_TAG);
                    for (unsigned long i = 0; i < fileSetDefinitions->length(); ++i) 
                    {
                        compileInterestingFilesSet(fileSetDefinitions->item(i));
                    }
                }
                else
                {
                    std::ostringstream msg;
                    msg << MSG_PREFIX << "failed to open config file '" << configFilePath << "'";
                    throw TskException(msg.str());
                }
            }
            else
            {
                std::ostringstream msg;
                msg << MSG_PREFIX << "config file'" << configFilePath << "' does not exist";
                LOGERROR(msg.str());
            }

            // Log the configuration.
            std::ostringstream msg;
            msg << MSG_PREFIX << "configured with " << fileSets.size() << " interesting file set definitions from '" << configFilePath << "'";
            LOGINFO(msg.str());
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            configFilePath.clear();
            std::ostringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
        catch (Poco::Exception &ex)
        {
            status = TskModule::FAIL;
            configFilePath.clear();
            std::ostringstream msg;
            msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
            LOGERROR(msg.str());
        }
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            configFilePath.clear();
            std::ostringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            configFilePath.clear();
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }

        return status;
    }

    /**
     * Module execution function. Looks for files matching the criteria specified in the 
     * configuration file and posts its findings to the blackboard.
     *
     * @returns Returns TskModule::FAIL if an error occurs, TskModule::OK otherwise.
     */
    TSK_MODULE_EXPORT TskModule::Status report()
    {
        TskModule::Status status = TskModule::OK;

        const std::string MSG_PREFIX = "InterestingFilesModule::report : ";
        try
        {
            if (configFilePath.empty())
            {
                // Initialization failed. The reason why was already logged in initialize().
                return TskModule::FAIL;
            }

            for (std::vector<InterestingFilesSet>::iterator fileSet = fileSets.begin(); fileSet != fileSets.end(); ++fileSet)
            {
                for (std::vector<string>::iterator condition = (*fileSet).conditions.begin(); condition != (*fileSet).conditions.end(); ++condition)
                {
                    vector<uint64_t> fileIds = TskServices::Instance().getImgDB().getFileIds(*condition);
                    for (size_t i = 0; i < fileIds.size(); i++)
                    {
                        TskBlackboardArtifact artifact = TskServices::Instance().getBlackboard().createArtifact(fileIds[i], TSK_INTERESTING_FILE_HIT);
                        TskBlackboardAttribute attribute(TSK_SET_NAME, "InterestingFiles", (*fileSet).description, (*fileSet).name);
                        artifact.addAttribute(attribute);
                    }
                }
            }
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
        catch (Poco::Exception &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
            LOGERROR(msg.str());
        }
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            std::ostringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }

        return status;
    }

    /**
     * Module cleanup function. Disposes of file search data created during initialization.
     *
     * @returns TskModule::OK
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        TskModule::Status status = TskModule::OK;

        const std::string MSG_PREFIX = "InterestingFilesModule::finalize : ";
        try
        {
            fileSets.clear();
        }
        catch (TskException &ex)
        {
            status = TskModule::FAIL;
            configFilePath.clear();
            std::ostringstream msg;
            msg << MSG_PREFIX << "TskException: " << ex.message();
            LOGERROR(msg.str());
        }
        catch (Poco::Exception &ex)
        {
            status = TskModule::FAIL;
            configFilePath.clear();
            std::ostringstream msg;
            msg << MSG_PREFIX << "Poco::Exception: " << ex.displayText();
            LOGERROR(msg.str());
        }
        catch (std::exception &ex)
        {
            status = TskModule::FAIL;
            configFilePath.clear();
            std::ostringstream msg;
            msg << MSG_PREFIX << "std::exception: " << ex.what();
            LOGERROR(msg.str());
        }
        catch (...)
        {
            status = TskModule::FAIL;
            LOGERROR(MSG_PREFIX + "unrecognized exception");
        }

        return status;
    }
}
