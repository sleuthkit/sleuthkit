/***************************************************************************
** This data and information is proprietary to, and a valuable trade secret
** of, Basis Technology Corp.  It is given in confidence by Basis Technology
** and may only be used as permitted under the license agreement under which
** it has been distributed, and in no other way.
**
** Copyright (c) 2014 Basis Technology Corp. All rights reserved.
**
** The technical data and information provided herein are provided with
** `limited rights', and the computer software provided herein is provided
** with `restricted rights' as those terms are defined in DAR and ASPR
** 7-104.9(a).
***************************************************************************/

#pragma once

#include <ctime>
#include <string>
#include <list>
#include "CollectionConfig.h"

using namespace std;

class ConfigMgr {
public:
    static const size_t FILEDATA_SIZE_THRESHOLD = 150UL * 1024UL * 1024UL;

    static ConfigMgr& getInstance()
    {
        static ConfigMgr    instance;
        return instance;
    }

    void setAgentVersion(const string & a_ver) { m_agentVersion = a_ver; };
    void setRunDate(time_t a_date) { m_runDate = a_date; };
    void setLastRunDate(time_t a_date) { m_lastRunDate = a_date; };
    /* True if we are analyzing a live device (not an image) */
    void setIsLiveSystem(bool a_bool) { m_isLiveSystem = a_bool; };
    
    void setTargetComputerSID(string a_str) { m_targetComputerSID = a_str; };
    void setInputPathName(string & a_pathName) { m_inputPathName = a_pathName; };
    void setImageName(string & a_imageName) { m_imageName = a_imageName; };
    void setFileContentReporting(bool a_bool) { m_reportFileContents = a_bool; }
    // void setRemoteServerMode(bool a_bool) { m_remoteServerMode = a_bool; }
     /* True if we are sending data over network back to Cyber Triage */
    void setSendDataOverNetwork(bool a_bool) { m_sendDataOverNetwork = a_bool; }
    void setUIServerAddr(string a_hostAddr) { m_uiServerHost = a_hostAddr; }
    void setUIServerAddrList(list<string> a_hostAddrList) { m_uiServerHostList = a_hostAddrList; }
    void setUIServerPortNum(int a_portNum) { m_uiServerPortNum = a_portNum; }
    void setRegressionTestMode(bool a_bool) { m_isRegressionTestMode = a_bool; }
    void setOutFilePathName(string a_str) { m_outFilePathName = a_str; };
    void setSaveTempFiles(bool a_bool) { m_saveTempFiles = a_bool; };
    void setDumpDbgData(bool a_bool) { m_dumpDbgData = a_bool; };
    void setReportOnlySuspStartupProgs(bool a_bool) { m_reportOnlySuspStartupProgs = a_bool; };
    void setShowCounters(bool a_bool) { m_showCounters = a_bool; };
    void setPrintDebugMsgs(bool a_bool) { m_printDebugMsgs = a_bool; };
    void setPrintErrorMsgs(bool a_bool) { m_printErrorMsgs = a_bool; };
    void setDummyAgentMode(bool a_bool) { m_dummyAgentMode = a_bool; }
    void setSessionID(string a_str) { m_sessionID = a_str; }
    void setSesssionKey(string a_str) { m_sessionKey = a_str; }
    void setIncident(string a_str) { m_incident = a_str; }
    void setSystemdriveEncrypted(bool a_bool) { m_systemdriveEncrypted = a_bool; };

    wstring getAgentExePath() const { return m_agentExePath; };
    wstring getAgentExeName() const { return m_agentExeName; };
    wstring getAgentEffectiveName() const { return m_agentEffectiveName; };
    string getAgentVersion() const { return m_agentVersion; };
    time_t getRunDate() const { return m_runDate; };
    time_t getLastRunDate() const { return m_lastRunDate; };
    bool isLiveSystem() const { return m_isLiveSystem; }
    string getImageName() const { return m_imageName; }
    string getInputPathName() const { return m_inputPathName; }
    bool sendDataOverNetwork() const { return  m_sendDataOverNetwork; }
    string getUIServerHost() const { return m_uiServerHost; }
    bool isUIServerHostList() const { return m_uiServerHostList.size() > 0; };
    list<string> getUIServerHostList() const { return m_uiServerHostList; }
    unsigned int getUIServerPortNum() const { return m_uiServerPortNum; }
    bool saveTempFiles() const { return m_saveTempFiles; }
    bool dumpDbgData() const { return m_dumpDbgData; }
    bool reportOnlySuspStartupProgs() const { return m_reportOnlySuspStartupProgs; };
    bool getShowCounters() const { return m_showCounters; };
    bool isPrintDebugMsgs() const { return m_printDebugMsgs; };
    bool isPrintErrorMsgs() const { return m_printErrorMsgs; };
    bool isDummyAgent() const { return m_dummyAgentMode; }
    string getSessionID() const { return m_sessionID; }
    string getSessionKey() const { return m_sessionKey; }
    string getIncident() const { return m_incident; }
    bool isSystemdriveEncrypted() const { return m_systemdriveEncrypted; }

    void setTargetComputerName(string a_str) { m_targetComputerName = a_str; };
    string getTargetComputerName() const { return m_targetComputerName; }

    string getTargetComputerSID() const { return m_targetComputerSID; }

    /** Get the local IP address used to connect to the server.
     * @returns empty string if not set / not used
     */
    string getLocalIp() const { return m_localIp; }
    void setLocalIp(char *ip) { m_localIp = ip; }

    int makeTempOutDir();
    void rmTempOutDir();
    string getTempOutDir() const { return m_tempOutDirPath; };
    string getOutFilePathName() const { return m_outFilePathName; };

    bool isFileContentReportingOn() const { return m_reportFileContents; }
    bool isRegressionTestMode() const {return m_isRegressionTestMode; }
    
    void getWinNTVersion(unsigned int &a_verMajor, unsigned int & a_verMinor);
    bool isWinNT62();
    bool isWinXPOrOlder();

    CollectionConfig &getCollectionConfig() {
        return m_collectionConfig;
    }

    void setCollectionConfig(CollectionConfig &config) {
        m_collectionConfig = config;
    }

private: 
    ConfigMgr();  
    ~ConfigMgr();
    ConfigMgr(ConfigMgr const&);             
    void operator=(ConfigMgr const&); 

    void setWinNTVersion();
    void findAgentExePath();

    string m_agentVersion;
    wstring m_agentExePath;
    wstring m_agentExeName;
	wstring m_agentEffectiveName;

    time_t m_runDate;
    bool m_isLiveSystem;
    bool m_isRegressionTestMode;    // when true, dont' print time stamps and progress counters that could change from run to run
    time_t m_lastRunDate;
    string m_targetComputerName;	// hostname of the target system
	string m_targetComputerSID;		// target system SID
	string m_inputPathName;			 // input param
    string m_imageName;
    string m_tempOutDirPath;
    string m_outFilePathName;		// pathname of output file, 
    bool m_reportFileContents;		// whether or not to report the contents of suspicious files

	bool m_sendDataOverNetwork;		// Agent is running on a machine remotely and communicating with UI over socket, as socket client

	string m_uiServerHost;			// remote UI server host name/IP
	list<string> m_uiServerHostList;// remote UI server IP list - in some cases, a list of IP addresses may be provided to try them all to see which works
	unsigned int m_uiServerPortNum;	// remote UI server port num, for collected JSON

    string m_localIp;       // local IP address for socket connection
	
	bool m_saveTempFiles;        // whether to save temporary outout files such as those from running other tools
    bool m_dumpDbgData;              // whether to dump debugging data
    bool m_reportOnlySuspStartupProgs;  // report only suspicious startup programs
    bool m_showCounters;
    bool m_printDebugMsgs;
	bool m_printErrorMsgs;
	bool m_dummyAgentMode;			// whether agent is running in "dummy" mode - i.e. return some static output
	string m_sessionID;				// session ID given by server
    string m_sessionKey;            // session key for sessions initiated by the agent
    string m_incident;              // incident for sessions initiated by the agent
	
    unsigned int m_winntVerMajor;
    unsigned int m_winntVerMinor;

	bool m_systemdriveEncrypted;	//records whether drive level encryption detected systemdrive C:

    CollectionConfig m_collectionConfig;
};
