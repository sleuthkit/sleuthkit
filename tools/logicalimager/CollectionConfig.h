#pragma once
#include <set>
#include <string>

class CollectionConfig
{
public:
    enum COLLECTION_TYPE {
        ENUM = 0,
        PROCESSES ,
        STARTUP_ITEMS,
        SCHEDULED_TASKS,
        NETWORK,
        NETWORK_CACHES,
        USERS,  
        PROGRAM_RUN,
        WEB,
        SYSTEM_CONFIG,
        USER_LOGINS,
        NETWORK_SHARES,
        ALL_FILES,
        MAX
        // NOTE: ANY CHANGE HERE NEEDS TO BE MADE TO THE BELOW LISTS TOO
    };

    CollectionConfig();
    
    ~CollectionConfig();

    // parse the CSV CLI arguments

    int CollectionConfig::setFromArgs(const std::string args);

    // string that maps the two letter CLI arguments to their type
    static std::string getCollectionTypeUsage();

    // Get string to save in the JSON about what was enabled
    std::string getSelectedTypesAsCsv();

    // @@@ We shoudl really merge the enum/string type/arguents into a single
    // struct like we do in TSK for the file system types...

    static const char *getCollectionTypeString(COLLECTION_TYPE enumVal)
    {
        static const char *CollectionTypeStrings[] = { 
            "ENUM",
            "PROCESSES",
            "STARTUP_ITEMS",
            "SCHEDULED_TASKS",
            "NETWORK",  // active connections & ports
            "NETWORK_CACHES",  
            "USERS",
            "PROGRAM_RUN",
            "WEB",
            "SYSTEM_CONFIG",
            "USER_LOGINS",
            "NETWORK_SHARES",
            "ALL_FILES" };

        return CollectionTypeStrings[enumVal];
    }

    // get the command line parsing arguments per type
    static const char *getCollectionTypeArg(COLLECTION_TYPE enumVal)
    {
        static const char *CollectionTypeStrings[] = {
            "enum", // not really specified by user
            "pr",//"PROCESSES",
            "st",//"STARTUP_ITEMS",
            "sc",//"SCHEDULED_TASKS",
            "nw",//"NETWORK",  // active connections & ports
            "nc",//"NETWORK_CACHES",
            "us",//"USERS",
            "ru",//"PROGRAM_RUN",
            "wb",//"WEB",
            "co",//"SYSTEM_CONFIG",
            "lo",//"USER_LOGINS",
            "ns",//"NETWORK_SHARES",
            "fs"//"ALL_FILES" 
        };

        return CollectionTypeStrings[enumVal];
    }

    /**
     * Return if the type is configured to be collected
     */
    bool shouldCollect(COLLECTION_TYPE type) const {
        return (m_collectTypes.count(type) > 0);
    }

    /**
     * return total number of types that are configured
     * to be collected. 
     */
    size_t getSize() const {
        return m_collectTypes.size();
    }

    /**
     * Remove items that are not relevant for dead images
     * @returns 1 if a requested type was removed
     */
    int removeLiveTypes() {
        // see if we are about to remove a type that the user asked for
        if (m_userSet) {
            if ((shouldCollect(PROCESSES)) ||
                shouldCollect(NETWORK) ||
                shouldCollect(NETWORK_CACHES)) {
                return 1;
            }
        }

        removeType(PROCESSES);
        removeType(NETWORK);
        removeType(NETWORK_CACHES);

        return 0;
    }

    /**
     * Add a single type to the collection
     */
    void addType(COLLECTION_TYPE type) {
        m_collectTypes.insert(type);
    }

    /**
     * remove a single type from the collection
     */
    void removeType(COLLECTION_TYPE type) {
        m_collectTypes.erase(type);
    }

private:
    std::set<COLLECTION_TYPE> m_collectTypes;
    void setAllTypes();
    bool m_userSet = false;
};
