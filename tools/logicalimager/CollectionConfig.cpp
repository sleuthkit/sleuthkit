#include "CollectionConfig.h"

CollectionConfig::CollectionConfig()
{
    setAllTypes();
}

//CollectionConfig::CollectionConfig(std::set<COLLECTION_TYPE> types)
//{
 //   m_skipTypes = types;
//    m_collectAll = false;
//}


CollectionConfig::~CollectionConfig()
{
}


void CollectionConfig::setAllTypes() {
    for (int i = 0; i < MAX; i++) {
        m_collectTypes.insert((COLLECTION_TYPE)i);
    }
}

/**
 * Set all of the collection settings based on comma separated CLI argument list
 */
int CollectionConfig::setFromArgs(const std::string args)
{
    char *pt;
    char argsbuf[128];
    if (args.length() > 128) {
        return 1;
    }
    strncpy(argsbuf, args.c_str(), 128);

    m_userSet = true;
    m_collectTypes.clear(); 
    m_collectTypes.insert(USERS);  // lots of things depend on this.  So, for now, always do it. 
    m_collectTypes.insert(ENUM); // We always do this.  Adding it makes sure the counts are correct.

    pt = strtok(argsbuf, ",");
    while (pt != NULL) {
        bool validType = false;
        // compare to the data types
        for (int i = 0; i < MAX; i++) {
            if (strcmp(pt, getCollectionTypeArg((COLLECTION_TYPE)i)) == 0) {
                m_collectTypes.insert((COLLECTION_TYPE)i);
                validType = true;
            }
        }
        
        if (validType == false) {
            return 1;
        }

        pt = strtok(NULL, ",");
    }

    if (m_collectTypes.size() == 0)
        return 1;

    return 0;
}

std::string CollectionConfig::getCollectionTypeUsage() {
    std::string usage;

    for (int i = 0; i < MAX; i++) {
        // we don't display this to the user
        if (i == ENUM)
            continue;
        std::string line = std::string(getCollectionTypeString((COLLECTION_TYPE)i)) + ": " + getCollectionTypeArg((COLLECTION_TYPE)i) + "\n";
        usage += line;
    }
    return usage;
}

std::string CollectionConfig::getSelectedTypesAsCsv() {
    std::string types = "";
    for (auto i = m_collectTypes.begin(); i != m_collectTypes.end(); i++) {
        if (i != m_collectTypes.begin())
            types += ", ";
        types += getCollectionTypeString(*i);
    }
    return types;
}
