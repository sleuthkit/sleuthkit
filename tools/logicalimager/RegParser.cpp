/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2010-2019 Brian Carrier.  All Rights reserved
**
** This software is distributed under the Common Public License 1.0
**
*/

#include <iostream>

#include "RegParser.h"

RegParser::RegParser(const RegHiveType::Enum aHiveType)
    : m_registryHive(NULL), m_rootKey(NULL) {
}

RegParser::RegParser(const std::wstring &filePath) {
    m_registryHive = new Rejistry::RegistryHiveFile(filePath);
    m_rootKey = m_registryHive->getRoot();
}

RegParser::~RegParser() {
    if (m_rootKey != NULL) {
        delete m_rootKey;
        m_rootKey = NULL;
    }

    if (m_registryHive != NULL) {
        delete m_registryHive;
        m_registryHive = NULL;
    }
}

/**
 * Load a hive
 *
 * @param aHiveFile TSK_FS_FILE hive file
 * @param aHiveType RegHiveType::Enum hive type
 * @returns 0 on success, -1 on error
 */
int RegParser::loadHive(TSK_FS_FILE *aHiveFile, RegHiveType::Enum aHiveType) {
    if (aHiveFile == NULL) {
        std::cerr << "Null pointer passed to RegParser::loadHive. loadHive() failed." << std::endl;
        return -1;
    }

    // If there already is a loaded hive, free it.
    if (m_registryHive != NULL) {
        delete m_registryHive;
        m_registryHive = NULL;
    }

    // Read the contents of the TSK_FS_FILE into memory.
    uint8_t *registryBuffer;
    if ((registryBuffer = (uint8_t *)malloc((size_t)aHiveFile->meta->size)) == NULL) {
        std::cerr << "loadHive(): Error allocating memory for hive file. tsk_fs_file_read() failed." << std::endl;
        return -1;
    }

    ssize_t bytesRead = tsk_fs_file_read(aHiveFile, 0, (char *)&registryBuffer[0],
        (size_t)aHiveFile->meta->size, TSK_FS_FILE_READ_FLAG_NONE);
    if (bytesRead != aHiveFile->meta->size) {
        std::cerr << "loadHive(): Error reading content from hive file. tsk_fs_file_read() failed." << std::endl;
        free(registryBuffer);
        return -1;
    }

    try {
        m_registryHive = new Rejistry::RegistryHiveBuffer(registryBuffer, (uint32_t)aHiveFile->meta->size);
    }
    catch (Rejistry::RegistryParseException &) {
        std::cerr << "loadHive(): Error creating RegistryHiveBuffer.  Likely because of memory size." << std::endl;
        free(registryBuffer);
        return -1;
    }
    catch (...) {
        std::cerr << "loadHive(): Error creating RegistryHiveBuffer (general exception).  Likely because of memory size." << std::endl;
        free(registryBuffer);
        return -1;
    }
    m_rootKey = m_registryHive->getRoot();

    free(registryBuffer);
    return 0;
}

/**
* Get the root key
*
* @param output aKey RegKey to receive the root key
* @returns 0 on success
*/
int RegParser::getRootKey(RegKey &aKey) {
    aKey.initialize(m_rootKey);
    return 0;
}

/**
 * Get the registry key for the given name.
 * The key name must contain one or more path elements,
 * e.g. "Setup" or "Setup\AllowStart\ProtectedStorage".
 * Path elements must be separated by the backslash
 * character. The key name will be evaluated relative to
 * the root of the registry file. The hive type (e.g.
 * HKLM\SYSTEM) must not be part of the key name.
 *
 * @param input keyName The name of the registry key.
 * @param output aKey A key object that will be populated with
 * data related to the key (if found).
 * @returns
 *      0 if the key was found.
 *      -1 if the key was not found.
 *      -2 if there was an error getting the key.
 */
int RegParser::getKey(const std::wstring &keyName, RegKey &aKey) {
    const Rejistry::RegistryKey *key = NULL;

    try {
        key = findKey(keyName);
    }
    catch (Rejistry::NoSuchElementException&) {
        return -1;
    }
    catch (Rejistry::RegistryParseException&) {
        return -2;
    }
    catch (...) {
        return -2;
    }

    aKey.initialize(key);
    return 0;
}

/**
 * Get the names of the subkeys (if any) for the given registry key.
 *
 * @param input keyName The name of the registry key to retrieve subkeys for.
 * See the RegParser::getKey documentation for key name format rules.
 * @param output subKeyNamesList The returned list of subkey names. The list
 * will be empty if the key contains no values.
 *
 * @returns
 *      0 if the key is found and data is being returned.
 *      -1 if the key is not found.
 *      -2 if there was an error getting the key.
 */
int RegParser::getSubKeys(const std::wstring &keyName, std::vector<std::wstring> &subKeyNamesList) {
    try {
        std::auto_ptr<Rejistry::RegistryKey const> key(findKey(keyName));

        Rejistry::RegistryKey::RegistryKeyPtrList subkeys = key->getSubkeyList();
        subKeyNamesList.reserve(subkeys.size());
        Rejistry::RegistryKey::RegistryKeyPtrList::iterator subKeyIter = subkeys.begin();

        for (; subKeyIter != subkeys.end(); ++subKeyIter) {
            subKeyNamesList.push_back((*subKeyIter)->getName());
        }

        for (subKeyIter = subkeys.begin(); subKeyIter != subkeys.end(); ++subKeyIter) {
            delete *subKeyIter;
        }
    }
    catch (Rejistry::NoSuchElementException&) {
        return -1;
    }
    catch (Rejistry::RegistryParseException&) {
        return -2;
    }
    catch (...) {
        return -2;
    }
    return 0;
}

/**
 * Get the subkeys (if any) for the given registry key.
 *
 * @param input keyName The name of the registry key to retrieve subkeys for.
 * See the RegParser::getKey documentation for key name format rules.
 * @param output subKeysList The returned list of subkeys. The list
 * will be empty if the key contains no values.
 *
 * @returns
 *      0 if the key is found and data is being returned.
 *      -1 if the key is not found.
 *      -2 if there was an error getting the key.
 */
int RegParser::getSubKeys(const std::wstring &keyName, std::vector<RegKey*> &subKeysList) {
    try {
        std::auto_ptr<Rejistry::RegistryKey const> key(findKey(keyName));

        Rejistry::RegistryKey::RegistryKeyPtrList subkeys = key->getSubkeyList();
        subKeysList.reserve(subkeys.size());
        Rejistry::RegistryKey::RegistryKeyPtrList::iterator subKeyIter = subkeys.begin();

        for (; subKeyIter != subkeys.end(); ++subKeyIter) {
            RegKey * key = new RegKey((*subKeyIter)->getName());
            key->initialize(*subKeyIter);
            subKeysList.push_back(key);
        }

        for (subKeyIter = subkeys.begin(); subKeyIter != subkeys.end(); ++subKeyIter) {
            delete *subKeyIter;
        }
    }
    catch (Rejistry::NoSuchElementException&) {
        return -1;
    }
    catch (Rejistry::RegistryParseException&) {
        return -2;
    }
    catch (...) {
        return -2;
    }
    return 0;
}

/**
 * Get the value associated with the given key name and value name.
 *
 * @param input keyName The name of the registry key in which to look for
 * the given value name.
 * See the RegParser::getKey documentation for key name format rules.
 * @param input valName The name of the value to retrieve.
 * @param output val A value object that has been populated with data related
 * to the value.
 *
 * @returns
 *      0 if the key/value was found.
 *      -1 if the key/value was not found.
 *      -2 if there was an error getting the key/value.
 */
int RegParser::getValue(const std::wstring &keyName, const std::wstring &valName, RegVal &val) {
    try {
        std::auto_ptr<Rejistry::RegistryKey const> key(findKey(keyName));
        Rejistry::RegistryValue *value = key->getValue(valName);
        val.initialize(value);
    }
    catch (Rejistry::NoSuchElementException&) {
        return -1;
    }
    catch (Rejistry::RegistryParseException&) {
        return -2;
    }
    catch (...) {
        return -2;
    }
    return 0;
}

/**
 * Get the value associated with the given value name relative to the given
 * key and optional subpath.
 *
 * @param input startKey The key in which to look for the given subpath and
 * value name.
 * See the RegParser::getKey documentation for key name format rules.
 * @param input subpathName An optional subpath under the given key from which
 * to retrieve the given value.
 * @param input valName The name of the value to retrieve.
 * @param output val A value object that has been populated with data related
 * to the value.
 *
 * @returns
 *      0 if the key/value was found.
 *      -1 if the key/value was not found.
 *      -2 if there was an error getting the key/value.
 */
int RegParser::getValue(const RegKey *startKey, const std::wstring &subpathName, const std::wstring &valName, RegVal &val) {
    if (NULL == startKey) {
        return -1;
    }

    try {
        std::auto_ptr<Rejistry::RegistryKey const> key(findKey(subpathName, startKey->getRegistryKey()));
        Rejistry::RegistryValue *value = key->getValue(valName);
        val.initialize(value);
    }
    catch (Rejistry::NoSuchElementException&) {
        return -1;
    }
    catch (Rejistry::RejistryException &) {
        return -2;
    }
    catch (...) {
        return -2;
    }
    return 0;
}

/**
* Get the values (if any) for the given registry key.
*
* @param input keyName The name of the registry key to retrieve values for.
* See the RegParser::getKey documentation for key name format rules.
* @param output valList The returned list of values. The list will be empty
* if the key contains no values.
*
* @returns
*      0 if the key was found.
*      -1 if the key was not found.
*      -2 if there was an error getting the key.
*/
int RegParser::getValues(const std::wstring &keyName, std::vector<RegVal *> &valList) {
    try {
        std::auto_ptr<Rejistry::RegistryKey const> key(findKey(keyName));

        Rejistry::RegistryValue::RegistryValuePtrList values = key->getValueList();
        valList.reserve(values.size());
        Rejistry::RegistryValue::RegistryValuePtrList::iterator valueIter = values.begin();

        for (; valueIter != values.end(); ++valueIter) {
            valList.push_back(new RegVal((*valueIter)));
        }

        for (valueIter = values.begin(); valueIter != values.end(); ++valueIter) {
            delete *valueIter;
        }
    }
    catch (Rejistry::NoSuchElementException&) {
        return -1;
    }
    catch (Rejistry::RegistryParseException&) {
        return -2;
    }
    catch (...) {
        return -2;
    }
    return 0;
}

/**
* Get all values (if any) for the given subpath relative to the given registry key.
*
* @param input startKey The registry key in which to look for the given subpath.
* @param input subPath The path to the key to retrieve values for.
* See the RegParser::getKey documentation for key name format rules.
* @param output valList The returned list of values. The list will be empty
* if the key contains no values.
*
* @returns
*      0 if the key was found.
*      -1 if the key was not found.
*      -2 if there was an error getting the key.
*/
int RegParser::getValues(const RegKey *startKey, const std::wstring &subpathName, std::vector<RegVal *> &valList) {
    if (NULL == startKey) {
        return -1;
    }

    try {
        std::auto_ptr<Rejistry::RegistryKey const> key(findKey(subpathName, startKey->getRegistryKey()));

        Rejistry::RegistryValue::RegistryValuePtrList values = key->getValueList();
        valList.reserve(values.size());
        Rejistry::RegistryValue::RegistryValuePtrList::iterator valueIter = values.begin();

        for (; valueIter != values.end(); ++valueIter) {
            valList.push_back(new RegVal((*valueIter)));
        }

        for (valueIter = values.begin(); valueIter != values.end(); ++valueIter) {
            delete *valueIter;
        }
    }
    catch (Rejistry::NoSuchElementException&) {
        return -1;
    }
    catch (Rejistry::RegistryParseException&) {
        return -2;
    }
    catch (...) {
        return -2;
    }
    return 0;
}

/**
* Find the key with the given name relative to the optional starting key.
*
* @param input keyName The name of the key to find.
* @param input startingKey An optional starting point from which to search.
* If not provided, the search will start at the root of the registry.
* @returns A pointer to the registry key.
* @throws Rejistry::NoSuchElementException if the key is not found.
* @throws Rejistry::RegistryParseException if there was an error getting
* the key.
*/
const Rejistry::RegistryKey *RegParser::findKey(const std::wstring &keyName, const Rejistry::RegistryKey *startingKey) const {

    if (keyName == m_rootKey->getName()) {
        return new Rejistry::RegistryKey(*m_rootKey);
    }

    std::vector<std::wstring> keyElements = splitKeyName(keyName);
    std::vector<std::wstring>::iterator keyIter = keyElements.begin();
    const Rejistry::RegistryKey *currentKey = startingKey == NULL ? m_rootKey : startingKey;

    // Navigate our way down the tree looking to locate the desired key.
    for (; keyIter != keyElements.end(); ++keyIter) {
        try {
            Rejistry::RegistryKey *nextKey = currentKey->getSubkey((*keyIter));
            if (currentKey != m_rootKey && currentKey != startingKey) {
                // Free the key we just searched (as long as its not the root or the starting key)
                delete currentKey;
            }
            currentKey = nextKey;
        }
        catch (Rejistry::NoSuchElementException&) {
            // If we fail on the root element, we will continue and
            // try the next element in the path. Otherwise we rethrow
            // the exception.
            if ((*keyIter) != m_rootKey->getName()) {
                throw;
            }
        }
    }

    if (currentKey == startingKey) {
        return new Rejistry::RegistryKey(*currentKey);
    }
    else {
        return currentKey;
    }
}

/**
 * Splits a key into its constituent parts. The key name parts must be
 * separated by the backslash character.
 *
 * @param input keyName The key to split.
 * @returns The split key elements as a vector of strings.
 */
std::vector<std::wstring> RegParser::splitKeyName(const std::wstring &keyName) const {
    std::vector<std::wstring> keys;
    size_t start = 0;
    size_t end = 0;

    while (start < keyName.size()) {
        size_t pos = keyName.find('\\', start);

        if (pos == std::wstring::npos) {
            end = keyName.size();
        }
        else {
            end = pos;
        }

        keys.push_back(std::wstring(&keyName[start], &keyName[end]));
        start = end + 1;
    }
    return keys;
}
