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
 * \file TskSystemProperties.h
 * Contains the definition of the TskSystemProperties class.
 */

#ifndef _TSK_SYSTEMPROPERTIES_H
#define _TSK_SYSTEMPROPERTIES_H

#include "framework_i.h"
#include <string>
#include <map>
#include <set>

/**
 * A base class for setting and retrieving system-wide name/value pairs.
 * Typically used to store system settings so that all modules and classes can
 * access the settings. Can be registered with and retrieved from TskServices.
 * The class is abstract; derived classes supply property storage options and 
 * implement the private virtual functions setProperty and getProperty (the 
 * class design makes use of Herb Sutter's Non-Virtual Interface [NVI] idiom).
 */
class TSK_FRAMEWORK_API TskSystemProperties
{
public:
    /**
     * The TSK Framework predefines a set of system properties. Some of these
     * properties are considered to be required. The Framework also supports
     * the use of system property macros formed by delimiting a predefined 
     * property name with '#' characters. These macros may be used to define
     * system properties in terms of other properties and may be included in 
     * module argument strings. For example, the following statement statements 
     * define the OUT_DIR system property as a directory relative to the 
     * PROG_DIR property.
     *
     *  TskSystemProperties sysProps;
     *  sysProps.set(TskSystemProperties::PROG_DIR, progDir);
     *  sysProps.set(TskSystemProperties::OUT_DIR, "#PROG_DIR#\\out");
     */
    enum PredefinedProperty
    {
        /** 
         * Directory where program using the framework is installed. 
         */
        PROG_DIR,

        /** 
         * Directory where configuration files and data can be found. 
         */
        CONFIG_DIR,
        
        /** 
          * Directory where plug-in and executable modules can be found. 
          */
        MODULE_DIR,

        /** 
         * Root output directory that all modules can write to. Should be a
         * shared location if framework is being used in a distributed 
         * environment. This is a REQUIRED property.
         */
        OUT_DIR,
        
        /** 
         * Path of the pipeline config file in use. 
         */ 
        PIPELINE_CONFIG_FILE,

        /** 
         * Hostname of central database (if one is being used). 
         */
        DB_HOST,

        /** 
         * Port of central database (if one is being used) 
         */
        DB_PORT,

        /** 
          * ID of this session.  The intended use of this is in a distributed
          * environment that is processing multiple images at the same time.
          * Each image would have a unique session ID. 
          */
        SESSION_ID,

        /** 
         * Currently executing task, e.g., file analysis, carving, etc. 
         */
        CURRENT_TASK,

        /** 
          * Used to assign a number in a sequence to some aspect of a task. 
          */ 
        CURRENT_SEQUENCE_NUMBER,

        /** 
         * The hostname of the computer on which the program is executing. 
         */
        NODE,

        /** 
         * The process identifier of the process running the program. 
         */
        PID,

        /** 
         * The time the process running the program began executing. 
         */
        START_TIME,

        /** 
         * The current system time. 
         */
        CURRENT_TIME,

        /** 
         * A combination of elements that define a unique identifier for the
         * current task. For example, this property might be defined to be a
         * string of the form <current task>_<hostname>_<pid>_<start time>. 
         */
        UNIQUE_ID,

        END_PROPS
    };

    /** 
     * Default constructor. 
     */
    TskSystemProperties();

    /** 
     * Destructor, virtual since this is an abstract base class. 
     */
    virtual ~TskSystemProperties() {}

    /**
     * Determines whether or not all required predefined system properties are
     * currently set.
     *
     * @return True if all required properties are set, false otherwise.
     */
    bool isConfigured() const;

    /** 
     * Associates a string value with a name.
     *
     * @param prop An element of the /ref PredefinedProperty enum.
     * @param value The value to associate with the name corresponding to the
     * /ref PredefinedProperty enum element.
     * @return Throws /ref TskException if prop is out of range.
     */
    void setW(PredefinedProperty prop, const std::wstring &value);
    
    /** 
     * Associates a string value with a name.
     *
     * @param name The name with which to associate the value.
     * @param value The value to associate with the name.
     * @return Throws /ref TskException if name is empty.
     */
    void setW(const std::wstring &name, const std::wstring &value);

    /** 
     * Associates a string value with a name.
     *
     * @param prop An element of the /ref PredefinedProperty enum.
     * @param value The value to associate with the name corresponding to the
     * /ref PredefinedProperty enum element.
     * @return Throws /ref TskException if prop is out of range.
     */
    void set(PredefinedProperty prop, const std::string &value);

    /** 
     * Associates a string value with a name.
     *
     * @param name The name with which to associate the value.
     * @param value The value to associate with the name.
     * @return Throws /ref TskException if name is empty.
     */
    void set(const std::string &name, const std::string &value);

    /** 
     * Retrieves the string value associated with the given name.
     *
     * @param prop An element of the /ref PredefinedProperty enum.
     * @returns String value corresponding to prop. Throws
     * /ref TskException if the requested value is for a required predefined 
     * property that is not set.
     */
    std::wstring getW(PredefinedProperty prop) const;

    /** 
     * Retrieves the string value associated with the given name.
     *
     * @param name Name of value to retrieve.
     * @returns String value or empty string if name was not found. 
     */
    std::wstring getW(const std::wstring &name) const;

    /** 
     * Retrieves the string value associated with the given name.
     *
     * @param prop An element of the /ref PredefinedProperty enum.
     * @returns String value corresponding to prop. Throws
     * /ref TskException if the requested value is for a required predefined 
     * property that is not set.
     */
    std::string get(PredefinedProperty prop) const;
    
    /** 
     * Retrieves the string value associated with the given name.
     *
     * @param name Name of value to retrieve.
     * @returns String value or empty string if name was not found. 
     */
    std::string get(const std::string &name) const;

    /**
     * Recursively expands any system property macros in a given string. 
     *
     * @param inputStr The input string.
     * @return A copy of the input string with all system property macros
     * expanded.
     */
    std::wstring expandMacrosW(const std::wstring &inputStr) const;

    /**
     * Recursively expands any system property macros in a given string. 
     *
     * @param inputStr The input string.
     * @return A copy of the input string with all system property macros
     * expanded.
     */
    std::string expandMacros(const std::string &inputStr) const;

private:
    // The calling functions ensure that name is non-empty. Implementations should of getProperty should return an empty string if there is no value associated with name.
    virtual void setProperty(const std::string &name, const std::string &value) = 0;
    virtual std::string getProperty(const std::string &name) const = 0;

    void expandMacros(const std::string &inputStr, std::string &outputStr, std::size_t depth) const;

    const static std::size_t MAX_DEPTH = 10;

    struct PredefProp
    {
        PredefProp(PredefinedProperty propId, const std::string &macroToken, bool propRequired) : id(propId), token(macroToken), required(propRequired) {}
        PredefinedProperty id;
        std::string token;
        bool required;
    };

    const static PredefProp predefinedProperties[]; 

    std::vector<std::string> predefPropNames;
    std::set<std::string> predefPropTokens;
    std::set<PredefinedProperty> requiredProps; 
};

#endif
