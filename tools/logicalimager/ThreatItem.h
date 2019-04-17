
/***************************************************************************
** This data and information is proprietary to, and a valuable trade secret
** of, Basis Technology Corp.  It is given in confidence by Basis Technology
** and may only be used as permitted under the license agreement under which
** it has been distributed, and in no other way.
**
** Copyright (c) 2014-2016 Basis Technology Corp. All rights reserved.
**
** The technical data and information provided herein are provided with
** `limited rights', and the computer software provided herein is provided
** with `restricted rights' as those terms are defined in DAR and ASPR
** 7-104.9(a).
***************************************************************************/

#pragma once

#include <list>
#include <string>

#include "tsk/auto/tsk_auto.h"
#include "ThreatDefs.h"
#include "ScheduledTaskAction.h"

using namespace std;

class O_FIELD {	// Output Fields and their "labels" in JSON output
public: 
	#define X(a, b) a
     enum Enum {
        #include "FieldNames.dat"
    };
    #undef X

	static const char *fieldNameStrings[200];
	static string toStr(O_FIELD::Enum e) { return string(O_FIELD::fieldNameStrings[e]);}
};

/*
 * Each reported threat is assigned a score. 
 * The score is computed based on the crieria that match to call out the item as a possible threat.
 */ 
namespace THREAT_SCORE {

	enum Enum {
        UNKNOWN,
        NONE,
		LOW,
		MEDIUM,
        HIGH
	};

	static char String[][100] = {
        "UNKNOWN",
        "NONE",
		"LOW",
		"MEDIUM",
        "HIGH"
	};
}

/*
 * Each reported Item has an associated identification method - how it was discovered
 *
 */ 
namespace CTExtractor {

	enum Enum {
        UNKNOWN,
        TSK,
		SYSTEM_API,
		EVTX_EXPORT,
		COLLECTION_TOOL
	};

	static char String[][100] = {
        "UNKNOWN",
        "TSK",
		"SystemAPI",
		"EvtxExport",
		"CollectionTool"
	};
}

/*
 * Each reported Item has an associated source - where it was discovered
 *
 */
namespace ItemSourceType {
	enum Enum {
        UNKNOWN,
		FILE_SYSTEM,
		FOLDER,
        FILE,
		REGISTRY_KEY,
		MEMORY,
		EVENT_LOG,
	};

	static char String[][100] = {
        "UNKNOWN",
        "FileSystem",
		"Folder",
		"File",
		"RegistryKey",
		"Memory",
		"EventLog",
	};
}

/*
 * An additional subtype may be used to better qualify the source, when needed
 *
 */
namespace ItemSourceSubType {
	enum Enum {
        UNKNOWN,
		MUI_CACHE,
		RUN_MRU,
        USER_ASSIST,
		APPCOMPAT_CACHE,
		PREFETCH_FILE,
		ACTIVITY_MODERATOR
	};

	static char String[][100] = {
        "UNKNOWN",
        "MUI Cache",
		"Run MRU",
		"UserAssist",
		"AppCompat Cache",
		"Prefetch file",
		"Activity Moderator"
	};
}


class ItemSource {

public:
	 ItemSource();
	 //ItemSource(ItemSourceType::Enum a_sourceType);
	
	ItemSourceType::Enum getSourceType() const { return m_sourceType; };
	string getSourceTypeStr() const { return ItemSourceType::String[m_sourceType]; };
	ItemSourceSubType::Enum getSourceSubtype() const { return m_sourceSubtype; };
	string getSourceSubtypeStr() const { return ItemSourceSubType::String[m_sourceSubtype]; };

	string getPath() const { return m_path; };
	string getKeyName() const { return m_keyName; };
	string getValueName() const { return m_valueName; };

	string getEvtlogName() const { return m_evtLogName; };
	unsigned long getEvtRecordID() const { return m_evtRecordID;}

	void clone(const ItemSource& a_other);

	void setSourceType(ItemSourceType::Enum a_type) { m_sourceType = a_type; };
	void setSourceSubtype(ItemSourceSubType::Enum a_subtype) { m_sourceSubtype = a_subtype; };

	void setPath(const string& a_path) {m_path = a_path; };

	void setKeyName(const string& a_name) {m_keyName = a_name; };
	void setValueName(const string& a_name) {m_valueName = a_name; };

	void setEvtlogName(const string& a_name) {m_evtLogName = a_name; };
	void setEvtRecordID( unsigned long a_id) { m_evtRecordID = a_id; };

protected:
	ItemSourceType::Enum m_sourceType;
	ItemSourceSubType::Enum m_sourceSubtype;	// a description/subtype to convey generic information about the source

	string m_path;
	string m_keyName;
	string m_valueName;

	string m_evtLogName;
	unsigned long m_evtRecordID;
};


/**
 * JSONReportedItemIntf defines an interface for all JSON reported items
 */
class JSONReportedItemIntf {
public:
	virtual string getItemJSONName() const = 0; 
	virtual list<string> getMissingFields() const = 0;   // get a list of names of essential missing fields


	void setExtractor(CTExtractor::Enum a_method) { m_CTExtractor = a_method; };

	CTExtractor::Enum getExtractor() const { return m_CTExtractor;};
	string getExtractorStr() const { return CTExtractor::String[m_CTExtractor];};
	ItemSource& getSource() { return m_srcInfo; };


protected:
	CTExtractor::Enum m_CTExtractor;
	ItemSource m_srcInfo;
};

class ThreatItem : public JSONReportedItemIntf {      // a threat item, pure virtual class

public:
    ThreatItem(const ThreatCategory* aCat);
    ~ThreatItem();

    virtual string getName() const = 0;   // some kind of readable identifier
	

    const ThreatCategory* getCategory() const { return m_threatCategory;}

    THREAT_SCORE::Enum  getMaxCriteriaScore() const;
    THREAT_SCORE::Enum  getOverrideScore() const { return m_overRideScore;};
    THREAT_SCORE::Enum  getScore() const;
	
	const string  &getUserAccountName() const { return m_userAccountName;};
    const string  &getUserSID() const { return m_userSID;};
    const string  &getUserDomainName() const { return m_userDomianName;};
	

	void setCategory(const ThreatCategory* aCat) { m_threatCategory = aCat;};
    void setUserAccountName(const string & a_name) { m_userAccountName = a_name;};
    void setUserSID(const string & a_sid) { m_userSID = a_sid;};
	void setUserDomainName(const string & a_name);
    void setOverrideScore(THREAT_SCORE::Enum a_score) { m_overRideScore = a_score; };

    void addCriteria(const ThreatCriteria* aCriteria);
    const std::list<const ThreatCriteria*>& getCriteriaList() const { return m_critList;}

protected:
    const ThreatCategory* m_threatCategory;
    std::list<const ThreatCriteria*> m_critList;
    THREAT_SCORE::Enum m_overRideScore;
    string m_userAccountName;
    string m_userSID;
    string m_userDomianName;

};


/*
 * SystemFileData: file contents of a system file
 */
class SystemFileData : public JSONReportedItemIntf  {
public:
    SystemFileData(const string& aFileType, const string& aFilePath);
    ~SystemFileData(void);

public:

	//overrides
	string getItemJSONName() const override { return "systemFile"; } ; 
	list<string> getMissingFields() const override;  

	void setFileData(unsigned char * a_dataBuf, ssize_t a_dataBufLen)  {  m_fileData = a_dataBuf; m_fileDataLen = a_dataBufLen; }

    string getPathName() const { return m_pathName; };
	string getFileType() const { return m_fileType; };
    const unsigned char *getFileData() const { return m_fileData;}
    ssize_t getFileDataLen() const { return m_fileDataLen;}

private:
	string m_fileType;
	string m_pathName;
    unsigned char *m_fileData;
    ssize_t m_fileDataLen;
};

class ThreatFile : public ThreatItem {      // a file threat, probably the most common type of ThreatItem

public:
    
    ThreatFile(const ThreatCategory* a_cat, const string a_name, const TSK_FS_ATTR *a_fs_attr);
    ~ThreatFile();
    
	//overrides
    string getName() const override { return m_pathName;}
	string getItemJSONName() const override { return "file"; } ; 
	list<string> getMissingFields() const override;  

    string getPathName() const { return m_pathName;}
    TSK_OFF_T getOffset() const { return m_fsOff; }
    TSK_INUM_T getMetaAddr() const { return m_metaAddr; }
    unsigned short getAttrID() const { return m_attrID; }

protected:
    ThreatFile(const ThreatCategory* a_cat, const string a_name, TSK_OFF_T volOff, TSK_INUM_T metaAddr, unsigned short a_attrID);
    string m_pathName;          // full pathname of the file
    TSK_OFF_T m_fsOff;          // offset of the FileSystem 
    TSK_INUM_T m_metaAddr;      // metaAddr to lookup the file in the image.
    unsigned short m_attrID;    // attribute ID
};

/**
 * File Content Collection status.
 *
 * This enum is also defined in Java side to parse the values and convert to user readable strings.
 */
namespace FileContent_Collection_Status  {
	enum Enum {
        COLLECTED,				// Found and collected the contents fot the file
		EMPTY_FILE,				// Found the file, file is empty
        NOT_FOUND,				// File with the given path name could not be found
        UNRESOLVED,				// File's path is unknown, cannot be resolved to an absolute path
        READ_ERROR,				// Error in reading file contents
		NOT_ATTEMPTED,			// Did not attempt to collect the content, not warranted
		NOT_REGULAR_FILE,		// Did not attempt, its not a regular file,
		FILE_TOO_LARGE	        // File is too large to include the contents in JSON
	};

	static char String[][100] = {
        "Collected",
		"EmptyFile",
		"NotFound",
		"Unresolved",
		"ReadError",
		"NotAttempted",
		"NotRegularFile",
		"FileTooLarge"
	};
};

namespace FileContent_Reported_Status  {
	enum Enum {
        REPORTED,           // File with extact meta address AND the pathname has been reported
        LINK_REPORTED,		// File with given meta address has been reported under another pathname -  
        NOT_REPORTED,       // File with the given meta address has not been reported at all yet.
        UNKNOWN
	};
};

class ThreatFileData : public ThreatFile {      // contents of a threat file. 
public:
    ThreatFileData(const ThreatCategory* a_cat, const string a_name, TSK_OFF_T volOff, TSK_INUM_T metaAddr, unsigned short a_attrID,  ssize_t a_fileDataLen = 0, unsigned char *a_fileData = NULL);
    ThreatFileData(const string a_name, TSK_OFF_T volOff, TSK_INUM_T metaAddr, unsigned short a_attrID, unsigned char *a_fileData);

	ThreatFileData(const string a_name, FileContent_Collection_Status::Enum a_fileContentCollectionStatus);

    ~ThreatFileData();

	list<string> getMissingFields() const override;

    void setFileData(unsigned char * a_dataBuf, ssize_t a_dataBufLen)  {  m_fileData = a_dataBuf; m_fileDataLen = a_dataBufLen; }

    /**
     * Set if the file has been sent to the JSON.  
     * @@@ BC: I think this method should go away.  It is only being used to save the results from DataCollector.  that is the more authoritative source. */
	void setFileContentReportedStatus(FileContent_Reported_Status::Enum a_status) { m_fileContentReportedStatus = a_status; }
	void setFileContentCollectionStatus(FileContent_Collection_Status::Enum a_status) { m_fileContentCollectionStatus = a_status; }

    const unsigned char *getFileData() const { return m_fileData;}
    ssize_t getFileDataLen() const { return m_fileDataLen;}

	FileContent_Reported_Status::Enum getFileContentReportedStatus() const { return m_fileContentReportedStatus; }
	FileContent_Collection_Status::Enum getFileContentCollectionStatus() const { return m_fileContentCollectionStatus; }
private:
    unsigned char *m_fileData;
    ssize_t m_fileDataLen;
	FileContent_Reported_Status::Enum m_fileContentReportedStatus;
	FileContent_Collection_Status::Enum m_fileContentCollectionStatus;

};

namespace CONFIG_ITEM_TYPE {

	enum Enum {
        STARTUP_PROGRAM,
		REG_ENTRY,
		SCHEDULED_TASK,
	};

	static char String[][100] = {
        "Startup Program",
		"Registry Entry",
		"Scheduled Task"

	};
}

class ConfigItem : public ThreatItem {      // a config item threat

public:
    ConfigItem(const ThreatCategory* a_cat, CONFIG_ITEM_TYPE::Enum a_type);
    ConfigItem(const ThreatCategory* a_cat, CONFIG_ITEM_TYPE::Enum a_type, const string a_name);
    ~ConfigItem();

    //overrides
    string getItemJSONName() const override { return "configItem"; };
    list<string> getMissingFields() const override;

    string getName() const { return m_name; }
    string getDetails() const { return m_details; }
    CONFIG_ITEM_TYPE::Enum getType() const { return m_configItemType; }
    string getTypeStr() const { return CONFIG_ITEM_TYPE::String[m_configItemType]; }
    bool knownArgs() const { return m_argsKnown; }
    string getArgs() const { return m_argsString; }
    
    /**
    * @returns Time in seconds since epoch
    */
    time_t getCreatedTime() const {return m_createdTime;}

    /**
    * @returns Time in seconds since epoch
    */
    time_t getModifiedTime() const { return m_modifiedTime; }

    void setName(string a_name) { m_name = a_name; }
    void setDetails(string a_details) { m_details = a_details; }
	void setArgs(const string& a_str) { m_argsString = a_str; m_argsKnown = true;  }

    /** 
     * @param ctime Time in seconds since epoch
     */
    void setCreatedTime(time_t ctime)  { m_createdTime = ctime; }
    /**
    * @param ctime Time in seconds since epoch
    */
    void setModifiedTime(time_t mtime) { m_modifiedTime = mtime; }



private:

	CONFIG_ITEM_TYPE::Enum m_configItemType;
    string m_name;              // regitry entry, INI key etc.
    string m_details;           // details of why the config item may be a threat
	bool m_argsKnown;			// to help distinguish between unknown args vs no args
	string m_argsString;
    time_t m_createdTime = 0;
    time_t m_modifiedTime = 0;
    
};


class SchTaskItem : public ConfigItem {      // a config item threat

public:
    SchTaskItem(const ThreatCategory* a_cat);
    SchTaskItem(const ThreatCategory* a_cat, const string a_name);
    ~SchTaskItem();
    
	//overrides
	string getItemJSONName() const override { return "configItem"; } ; 
	list<string> getMissingFields() const override;

	void setTaskName(const string& aName) {  m_taskName = aName; }
	void setTriggers(const string& aStr) {  m_triggers = aStr; }
	void setEnabled(bool aBool) { m_enabled = aBool; }
	void setActionsList(vector<const ScheduledTaskAction *> *actionsList) { 
		m_pActionsList = actionsList;
	}

	string getTaskName() const { return m_taskName; }
	string getTriggers() const { return m_triggers; }
	bool isEnabled() const { return m_enabled; }
	vector<const ScheduledTaskAction *> & getActionsList()const { return *m_pActionsList; }

private:

    string m_taskName;         
    string m_triggers;          
    bool m_enabled; 
	vector<const ScheduledTaskAction *> *m_pActionsList;
};


namespace EVENT_TYPE {

	enum Enum {
        PROGRAM_EXECUTION,
		SCH_TASK_EXECUTION,
		USER_LOGIN,
	};

	static char String[][100] = {
        "Program Run",
		"Scheduled Task Run",
		"User Login"
	};
}



class ThreatEvent : public ThreatItem {      // an event that may pose or indicate a possible threat to the system

public:
    ~ThreatEvent();
    
	//overrides
	list<string> getMissingFields() const override;
	string getItemJSONName() const override { return "event"; } ;

    void setTime(time_t aTime) { m_evtTime = aTime; };
	void setFractionSeconds(unsigned long aLong) { m_fractionSeconds = aLong; };

    string getName() const { return m_name;}
    time_t getTime() const { return m_evtTime; }
	unsigned long getFractionSeconds() const { return m_fractionSeconds; };
   
    EVENT_TYPE::Enum getType() const { return m_evtType;}
    string getTypeStr() const { return EVENT_TYPE::String[m_evtType];}
    string getEventTimeStr() const;

protected:
    ThreatEvent(const ThreatCategory* a_cat, const string a_name, EVENT_TYPE::Enum a_evtType);

    EVENT_TYPE::Enum m_evtType;
    string m_name;              
    time_t m_evtTime;
	unsigned long m_fractionSeconds;
   
};


class ProgExecEvent : public ThreatEvent {      // an event that may pose or indicate a possible threat to the system

public:
    ProgExecEvent(const ThreatCategory* a_cat, const string a_name);
    ProgExecEvent(const ThreatCategory* a_cat, const string a_name, EVENT_TYPE::Enum a_evtType);
    ~ProgExecEvent();
    
	//overrides
	list<string> getMissingFields() const override;

    string getPathName() const { return m_pathName;}
	bool knownArgs() const { return m_argsKnown; } 
	string getArgs() const { return m_argsString; } 

    void setPathName(string aPathName) { m_pathName = aPathName; };
	void setArgs(const string& a_str) { m_argsString = a_str; m_argsKnown = true;  }

private:
    string m_pathName; 
	bool m_argsKnown;			// to help distinguish between unknown args vs no args
	string m_argsString;
};

class SchTaskExecEvent : public ProgExecEvent {     

public:
    SchTaskExecEvent(const ThreatCategory* a_cat, const string a_taskPathName);
    ~SchTaskExecEvent();
    
	//overrides
	list<string> getMissingFields() const override;

    string getTaskName() const { return m_taskName;}
	string getTaskPathName() const { return m_taskPathName;}
   
	void setTaskName(const string& aTaskName)  { m_taskName = aTaskName;}
private:
    string m_taskName;   
	string m_taskPathName;
};

namespace LOGIN_STATE {

	enum Enum {
        UNKNOWN,
        LOGGED_OUT, // known to have logged out
		LOGGED_IN,  // known to be logged in 
	};

}

namespace DIRECTION {

	enum Enum {
        UNKNOWN,
        INCOMING,	
		OUTGOING,  
	};

	static char String[][100] = {
        "UNKNOWN",
        "Incoming",
		"Outgoing"
	};

}

namespace LOGIN_TYPE {

	enum Enum {
        LT_UNKNOWN,
        LT_LOCAL_INTERACTIVE,	// user logs in locally via UI
		LT_REMOTE_INTERACTIVE,  // User logs in remotely via UI, RDP, ssh
		LT_NEW_CREDENTIALS,     // A logged in user runs a command with Runas, using a different user's credentials
		LT_NETWORK,				// non interactive remote login, e.g. drive mount, shared file printer access
		LT_SYSTEM_LOGIN,		// local login session created by the OS, e.g. SERVICE account login to start a service

	};

	static char String[][100] = {
        "LT_UNKNOWN",
        "LT_LOCAL_INTERACTIVE",
		"LT_REMOTE_INTERACTIVE",
		"LT_NEW_CREDENTIALS",
		"LT_NETWORK",
		"LT_SYSTEM_LOGIN"
	};

}

class UserLoginEvent : public ThreatEvent {

public:
    UserLoginEvent(const ThreatCategory* a_cat, const string a_name);
    ~UserLoginEvent();

	//overrides
	list<string> getMissingFields() const override;

    void setSrcHost(string& aHost);
    string getSrcHost() const { return m_srcHost;};

	void setSrcHostFQDN(string& aFQDN) { m_srcHostFQDN = aFQDN; };
    string getSrcHostFQDN() const { return m_srcHostFQDN;};

    void setCurrentLoginState(LOGIN_STATE::Enum a_state) { m_currLoginState = a_state; };
    LOGIN_STATE::Enum getCurrentLoginState() const { return m_currLoginState; };
    string getCurrentLoginStateStr() const;

	DIRECTION::Enum getLoginDirection() const { return m_loginDirection; };
	string getLoginDirectionStr() const { return DIRECTION::String[m_loginDirection]; };

	void setLoginType(LOGIN_TYPE::Enum a_loginType) { m_loginType = a_loginType; };
	LOGIN_TYPE::Enum getLoginType() const { return m_loginType; };
	string getLoginTypeStr() const { return LOGIN_TYPE::String[m_loginType]; };

	void setProcessPathname(const string& aPathname) {m_processPathname = aPathname; };
	string getProcessPathname() const {return m_processPathname;};

	void setLogonProcessName(const string& aName) {m_logonProcessName = aName; };
	string getLogonProcessName() const {return m_logonProcessName;};

	void setAuthenticationPkg(const string& aPkg) { m_authenitcaionPackage = aPkg; };
	string getAuthenticationPkg() const { return m_authenitcaionPackage; }

    bool isSameAs(UserLoginEvent& aOtherEvent) const;

private:
    string m_srcHost;
	string m_srcHostFQDN;
    LOGIN_STATE::Enum m_currLoginState;
	DIRECTION::Enum m_loginDirection;
	LOGIN_TYPE::Enum m_loginType;

	string m_processPathname; 
	string m_authenitcaionPackage;
	string m_logonProcessName;


};

class OutgoingRDPLoginEvent : public ThreatEvent {

public:
    OutgoingRDPLoginEvent(const ThreatCategory* a_cat, const string a_name);
    ~OutgoingRDPLoginEvent();

	//Overrides
	list<string> getMissingFields() const override;   // get a list of names of essential missing fields

    void setTgtHost(string& aHost) ;
	void setTgtHostFQDN(string& aFQDN) { m_tgtHostFQDN = aFQDN; };
    void setRemoteUserName(string& aUser) { m_remoteUserName = aUser; };
    void setRemoteUserDomain(string& aDomain) { m_remoteUserDomain = aDomain; };
	void setProcessPathname(const string& aPathname) {m_processPathname = aPathname; };

    string getTgtHost() const { return m_tgtHost;};
	string getTgtHostFQDN() const { return m_tgtHostFQDN; };
    string getRemoteUserName() const { return m_remoteUserName;};
    string getRemoteUserDomain() const { return m_remoteUserDomain;};
	DIRECTION::Enum getLoginDirection() const { return m_loginDirection; };
	string getLoginDirectionStr() const { return DIRECTION::String[m_loginDirection]; };

	void setLoginType(LOGIN_TYPE::Enum a_loginType) { m_loginType = a_loginType; };
	LOGIN_TYPE::Enum getLoginType() const { return m_loginType; };
	string getLoginTypeStr() const { return LOGIN_TYPE::String[m_loginType]; };
	string getProcessPathname() const {return m_processPathname;};

private:
    string m_tgtHost;
	string m_tgtHostFQDN;
    string m_remoteUserName;
    string m_remoteUserDomain;
	DIRECTION::Enum m_loginDirection;
	LOGIN_TYPE::Enum m_loginType;
	string m_processPathname; 
};


class Process: public ThreatItem {

public:
     Process(const ThreatCategory* a_cat, string aProcName, long aPid);
    ~Process();

	//overrides
    string getName() const override { return m_procName;}
	string getItemJSONName() const override { return "process"; } ;
	list<string> getMissingFields() const override;

    void setParentProcId(long aPid) {m_parentProcId = aPid; };
    void setPathName(string aExePathName) {m_pathName = aExePathName; };
    void setCreationTime(time_t aTime) {m_creationTime = aTime; };
	void setIsSvc(bool a_bool) { m_isSvc = a_bool; };
	void setArgs(const string& a_str) { m_argsString = a_str; m_argsKnown = true;  }
   
    string getProcName() const { return m_procName;}
    string getPathName() const { return m_pathName; }
    long getProcId() const { return m_procId; }
    long getParentProcId() const { return m_parentProcId; }
    time_t getCreationTime() const {return m_creationTime; };
	bool isSvc() const { return m_isSvc; };
	bool knownArgs() const { return m_argsKnown; } 
	string getArgs() const { return m_argsString; } 

private:
    string m_procName;      // name only
    string m_pathName;		// full path and name
    long   m_procId;
    long   m_parentProcId;
    bool   m_isElevated;	// running with elevated privs
	bool	m_isSvc;			// is a service 
    time_t m_creationTime;
	bool	m_argsKnown;			// to help distinguish between unknown args vs no args
	string m_argsString;
};


namespace NW_CONN_DESCRIPTOR_TYPE {

	enum Enum {
        UNKNOWN,
        ACTIVE_NETWORK_CONNECTION,
		LISTENING_PORT,
        DNS_CACHE,
        ARP_CACHE,
        ROUTING_TABLE,
        MOUNTED_DRIVE
	};

	static char String[][100] = {
        "UNKNOWN",
        "activeNetworkConnection",
		"listeningPort",
        "dnsCacheEntry",
        "arpCacheEntry",
        "routingTableEntry",
        "mountedDrive"
	};
}


/*
 * NetworkConnectionDescriptorBase: abstract base class for things that look like a N/W connection, or involves a remote host.
 */
class NetworkConnectionDescriptorBase : public ThreatItem {      // an event that may pose or indicate a possible threat to the system

public:
    NetworkConnectionDescriptorBase(const ThreatCategory* a_cat, NW_CONN_DESCRIPTOR_TYPE::Enum a_descrType );
    ~NetworkConnectionDescriptorBase();
    
    NW_CONN_DESCRIPTOR_TYPE::Enum getDescritorType() const { return m_descriptorType;}
    string getDescriptorTypeStr() const { return NW_CONN_DESCRIPTOR_TYPE::String[m_descriptorType];}
    
    virtual string getName() const = 0;   // some kind of readable identifier
	string getItemJSONName() const override { return "nwConnectionDescriptor"; } ;
	virtual list<string> getMissingFields() const = 0;

	string getConnectionType() const { return m_connType;}
	void setConnectionType(string & aConnType) {m_connType = aConnType; };

    void setLocalIP(string & aIP) {m_localIP = aIP; };
    void setLocalHostName(string & aHostName);
	void setLocalHostFQDN(string & aFQDN) {m_localHostFQDN = aFQDN; };
    void setLocalDomain(string & aDomain) {m_localDomain = aDomain; };
	void setLocalPort(long aPort) {m_localPort = aPort; };
   
    void setRemoteIP(string & aIP) {m_remoteIP = aIP; };
    void setRemoteHostName(string & aHostName);
	void setRemoteHostFQDN(string & aFQDN) {m_remoteHostFQDN = aFQDN; };
    void setRemoteDomain(string & aDomain) {m_remoteDomain = aDomain; };
	void setRemotePort(long aPort) {m_remotePort = aPort; };

    string getLocalIP() const { return m_localIP; };
    string getLocalHostName() const { return m_localHostName; }
	string getLocalHostFQDN() const { return m_localHostFQDN; }
    string getLocalDomain() const { return m_localDomain; }
	long getLocalPort() const { return m_localPort;};

    string getRemoteIP() const { return m_remoteIP; };
    string getRemoteHostName() const { return m_remoteHostName; }
	string getRemoteHostFQDN() const { return m_remoteHostFQDN; }
    string getRemoteDomain() const { return m_remoteDomain; }
    long getRemotePort() const { return m_remotePort;};

protected:
    NW_CONN_DESCRIPTOR_TYPE::Enum m_descriptorType;

	string m_connType;          // tcp/udp 

    string m_localIP; 
    string m_localHostName;
	string m_localHostFQDN;
    string m_localDomain;
	long   m_localPort;

    string m_remoteIP;   
    string m_remoteHostName;
	string m_remoteHostFQDN;
    string m_remoteDomain;
    long   m_remotePort;

};

/**
* ActiveNetworkConnection class. Depicts an established tcp connection with a known remote end.
*/
class ActiveNetworkConnection: public NetworkConnectionDescriptorBase {

public:
     ActiveNetworkConnection(const ThreatCategory* a_cat, string a_connType);
    ~ActiveNetworkConnection();

	// Overrides
    string getName() const override { return m_localIP + ":" + std::to_string((_Longlong)m_localPort);}
	list<string> getMissingFields() const override;

    void setProcId(long aPid) {m_procId = aPid; };
    void setState(string & a_state) {m_connState = a_state;}
	void setTime(time_t aTime) { m_connectionTime = aTime; };
  
    long getPID() const { return m_procId;}
    string getState() const { return m_connState; }
    
	time_t getConnectionTime() const { return m_connectionTime;};

private:
	time_t m_connectionTime;
    long   m_procId;
    string m_connState;
};

/**
* ListeningPort class. Depicts an open UDP port or a listening TCP port wating for a any remote end to connect. 
*/
class ListeningPort: public NetworkConnectionDescriptorBase {

public:
     ListeningPort(const ThreatCategory* a_cat, string a_portType);
    ~ListeningPort();

	// Overrides
    string getName() const override { return m_localIP + ":" + std::to_string((_Longlong)m_localPort);}
	list<string> getMissingFields() const override;

    void setProcId(long aPid) {m_procId = aPid; };
	void setTime(time_t aTime) { m_openTime = aTime; };

    long getPID() const { return m_procId;}
	time_t getOpenTime() const { return m_openTime;};
	
private:
    long   m_procId;
	time_t m_openTime;

};


class DNSCacheEntry: public ThreatItem {
public:
     DNSCacheEntry(const ThreatCategory* a_cat, string a_hostName);
    ~DNSCacheEntry();

	// Overrides
    string getName() const override { return m_hostName;}
	list<string> getMissingFields() const override;
	string getItemJSONName() const override { return "dnsCacheEntry"; } ;
	

	void setHostName(string &a_hostName);
    void addIP(string &aIP) {m_IPs.push_back(aIP); };
    void setRecType(unsigned int a_type) { m_dnsRecType = a_type;}
	void setHostFQDN(string & aFQDN) { m_hostFQDN = aFQDN;}

    string getHostName() const { return m_hostName;}
	string getHostFQDN() const { return m_hostFQDN;}

    list<string> getIPs() const { return m_IPs; };
    unsigned short getRecType() const { return m_dnsRecType; }

private:
    string m_hostName;
	string m_hostFQDN;
    list<string> m_IPs;
    unsigned int m_dnsRecType;
    unsigned long m_ttl;

};


class ARPCacheEntry: public ThreatItem {
public:
     ARPCacheEntry(const ThreatCategory* a_cat, string a_hostIP);
    ~ARPCacheEntry();
    
	//Overrides
    string getName() const override { return m_hostIP;}
	string getItemJSONName() const override { return "arpCacheEntry"; } ;
	list<string> getMissingFields() const override;

    void setPhysAddr(string a_addr) { m_physAddr = a_addr;}

    string getHostIP() const { return m_hostIP;}
    string getPhysAddr() const { return m_physAddr; }

private:
    string m_hostIP;
    string m_physAddr;
};


class RoutingTableEntry: public ThreatItem {
public:
     RoutingTableEntry(const ThreatCategory* a_cat, string a_hostIP);
    ~RoutingTableEntry();
    
	// Overrides
	string getName() const override { return m_hostIP;}
	string getItemJSONName() const override { return "routingTableEntry"; } ;
	list<string> getMissingFields() const override;

    void setNextHopAddr(string a_addr) { m_nextHopAddr = a_addr;}

   
    string getHostIP() const { return m_hostIP;}
    string getNextHopAddr() const { return m_nextHopAddr;}

private:
    string m_hostIP;        // dest/remote addr
    string m_nextHopAddr;   // G/W or next hop addr
};




class MountedDriveEntry: public NetworkConnectionDescriptorBase {
public:
     MountedDriveEntry(const ThreatCategory* a_cat, string a_hostName, string a_shareName);
    ~MountedDriveEntry();
    
	// Overrides
	string getName() const override { return "\\\\" + getRemoteHostName() + "\\" + m_shareName;}
	list<string> getMissingFields() const override;

	void setSharedFolder(string a_folder) { m_sharedFolder = a_folder;}

   
	string getSharedFolder() const { return m_sharedFolder;}

    string getShareName() const { return m_shareName;}

    bool isSameAs(MountedDriveEntry& aOtherDrive) const;

private:
    string m_shareName;         // share name
	string m_sharedFolder;		// shared folder pathname, relative to shareName
};
