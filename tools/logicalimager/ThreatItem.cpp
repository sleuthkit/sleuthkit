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

#include <algorithm>
#include "ThreatItem.h"
//#include "ThreatRulesManager.h"
#include "TsKHelper.h"

using namespace std;


#define X(a, b) b
const char *O_FIELD::fieldNameStrings[200] = {
	#include  "FieldNames.dat"
};
#undef X



ItemSource::ItemSource() {
	m_sourceType = ItemSourceType::UNKNOWN;
	m_sourceSubtype = ItemSourceSubType::UNKNOWN;

	m_path.clear();
	m_keyName.clear();
	m_valueName.clear();
	m_evtLogName.clear();
	m_evtRecordID = 0;
}

void ItemSource::clone(const ItemSource& a_other) {
	m_sourceType = a_other.getSourceType();
	m_sourceSubtype = a_other.getSourceSubtype();

	m_path = a_other.getPath();
	m_keyName = a_other.getKeyName();
	m_valueName = a_other.getValueName();

	m_evtLogName = a_other.getEvtlogName();
	m_evtRecordID = a_other.getEvtRecordID();
}


SystemFileData::SystemFileData(const string& aFileType, const string& aFilePath) {
	m_fileType = aFileType;
	m_pathName = aFilePath;
}
SystemFileData::~SystemFileData(void) {

}

list<string> SystemFileData::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_pathName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PATH));
	if (NULL == m_fileData)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::FILE_CONTENT));
	if (m_fileDataLen <= 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::FILE_CONTENT_LEN));

	return missingFieldsList;
}


ThreatItem::ThreatItem(const ThreatCategory* aCat) :
	m_threatCategory(aCat),
	m_overRideScore(THREAT_SCORE::UNKNOWN),
	m_userAccountName(""),
	m_userSID("")
{
	m_CTExtractor = CTExtractor::UNKNOWN;
	m_srcInfo.setSourceType(ItemSourceType::UNKNOWN);
}

ThreatItem::~ThreatItem()
{
	m_threatCategory = NULL;
	m_critList.clear();
}


void ThreatItem::addCriteria(const ThreatCriteria* aCrit)
{
	if (aCrit) {
		m_critList.push_back(aCrit);
	}
}


/*
 * Calculates and return the threat item score based on the criteria matched.
 * Currently finds the criteria with the highest score and then returns that score
 */
THREAT_SCORE::Enum ThreatItem::getMaxCriteriaScore() const
{
	THREAT_SCORE::Enum itemScore = THREAT_SCORE::UNKNOWN;

	// find the highest score amonf criteria
	CRITERIA_SCORE::Enum maxCritScore = CRITERIA_SCORE::UNKNOWN;
	for (list<const ThreatCriteria*>::const_iterator i = m_critList.begin(); i != m_critList.end(); i++) {
		if (static_cast<unsigned short> ((*i)->getScore()) > static_cast<unsigned short>(maxCritScore))
			maxCritScore = (*i)->getScore();
	}

	// Currently its a simple linear mapping between CRITERIA_SCORE ==> THREAT_SCORE
	itemScore = static_cast<THREAT_SCORE::Enum> (maxCritScore);

	return itemScore;
}

THREAT_SCORE::Enum  ThreatItem::getScore() const {

	return  (THREAT_SCORE::UNKNOWN != this->getOverrideScore() ? this->getOverrideScore() : this->getMaxCriteriaScore());
}

void ThreatItem::setUserDomainName(const string &a_name) {
		m_userDomianName = CyberTriageUtils::normalizeLoginDomain(a_name);
}

ThreatFile::ThreatFile(const ThreatCategory* a_cat, const string a_pathName, TSK_OFF_T a_volOff, TSK_INUM_T a_metaAddr, unsigned short a_attrID) :
	ThreatItem(a_cat),
	m_pathName(a_pathName),
	m_fsOff(a_volOff),
	m_metaAddr(a_metaAddr),
	m_attrID(a_attrID)
{


}

ThreatFile::ThreatFile(const ThreatCategory* a_cat, const string a_pathName, const TSK_FS_ATTR *a_fs_attr) :
    ThreatItem(a_cat),
    m_pathName(a_pathName),
    m_fsOff(a_fs_attr->fs_file->fs_info->offset),
    m_metaAddr(a_fs_attr->fs_file->meta->addr),
    m_attrID(a_fs_attr->id)
{
    string userName("");
    string userDomain("");
    if (0 == TSKHelper::getFileUser(a_fs_attr->fs_file, a_pathName, userName, userDomain)) {
        m_userAccountName = userName;
        m_userDomianName = userDomain;
    }
    m_userSID = TSKHelper::getFileUserSID(a_fs_attr->fs_file);

}

ThreatFile:: ~ThreatFile()
{

};


list<string> ThreatFile::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_pathName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PATH));

	return missingFieldsList;
}

ThreatFileData::ThreatFileData(const ThreatCategory* a_cat, const string a_name, TSK_OFF_T volOff, TSK_INUM_T metaAddr, unsigned short a_attrID, ssize_t a_fileDataLen, unsigned char *a_fileData) :
	ThreatFile(a_cat, a_name, volOff, metaAddr, a_attrID)
{
	m_fileData = a_fileData;
	m_fileDataLen = a_fileDataLen;

	m_fileContentReportedStatus = FileContent_Reported_Status::NOT_REPORTED;
}

ThreatFileData::ThreatFileData(const string a_name, FileContent_Collection_Status::Enum a_fileContentCollectionStatus) :
	ThreatFile(ThreatRulesManager::getInstance().getCategory(CAT_NONE), a_name, 0, 0, 0)
{
	m_fileData = 0;
	m_fileDataLen = 0;

	m_fileContentReportedStatus = FileContent_Reported_Status::NOT_REPORTED;

	m_fileContentCollectionStatus = a_fileContentCollectionStatus;
}

ThreatFileData::~ThreatFileData()
{
	// delete the file data buffer
	if (m_fileData) {
		free(m_fileData);
		m_fileData = NULL;
	}

}

list<string> ThreatFileData::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_pathName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PATH));

	/***
	if (NULL == m_fileData)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::FILE_CONTENT));
	if (m_fileDataLen <= 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::FILE_CONTENT_LEN));
	***/

	return missingFieldsList;
}


ConfigItem::ConfigItem(const ThreatCategory* a_cat, CONFIG_ITEM_TYPE::Enum a_type) :
	ThreatItem(a_cat),
	m_configItemType(a_type),
	m_argsKnown(false)
{

}

ConfigItem::ConfigItem(const ThreatCategory* a_cat, CONFIG_ITEM_TYPE::Enum a_type, const string a_name) :
	ThreatItem(a_cat),
	m_configItemType(a_type),
	m_name(a_name),
	m_argsKnown(false)
{
}
ConfigItem::~ConfigItem() {
}

list<string> ConfigItem::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_name.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::DESCRIPTION));

	return missingFieldsList;
}

SchTaskItem::SchTaskItem(const ThreatCategory* a_cat) :
	ConfigItem(a_cat, CONFIG_ITEM_TYPE::SCHEDULED_TASK) {
}
SchTaskItem::SchTaskItem(const ThreatCategory* a_cat, const string a_name) :
	ConfigItem(a_cat, CONFIG_ITEM_TYPE::SCHEDULED_TASK, a_name)
{
}
SchTaskItem::~SchTaskItem() {
}


list<string> SchTaskItem::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_taskName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::NAME));

	return missingFieldsList;
}

ThreatEvent::ThreatEvent(const ThreatCategory* a_cat, const string a_name, EVENT_TYPE::Enum a_evtType) :
	ThreatItem(a_cat),
	m_name(a_name)
{
	m_evtTime = 0;
	m_fractionSeconds = 0;
	m_evtType = a_evtType;
}


ThreatEvent:: ~ThreatEvent()
{

};

string ThreatEvent::getEventTimeStr() const {
	return getTimeStr(m_evtTime, m_fractionSeconds);
}

list<string> ThreatEvent::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (0 == m_evtTime)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::TIME));

	return missingFieldsList;
}

ProgExecEvent::ProgExecEvent(const ThreatCategory* a_cat, const string a_name) :
	ThreatEvent(a_cat, a_name, EVENT_TYPE::PROGRAM_EXECUTION),
	m_argsKnown(false)
{

}
ProgExecEvent::ProgExecEvent(const ThreatCategory* a_cat, const string a_name, EVENT_TYPE::Enum a_evtType) :
	ThreatEvent(a_cat, a_name, a_evtType) {
}

ProgExecEvent::~ProgExecEvent() {
}

list<string> ProgExecEvent::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	// Program exec events are generally obtained from Registry and as such dont have a time
	//if (0 == m_evtTime)
	//	missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::TIME));
	if (m_pathName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PATH));
	//if (m_userAccountName.empty())
	//	missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::USER_ID));


	return missingFieldsList;
}


SchTaskExecEvent::SchTaskExecEvent(const ThreatCategory* a_cat, const string a_taskPathName) :
	ProgExecEvent(a_cat, a_taskPathName, EVENT_TYPE::SCH_TASK_EXECUTION)
{
	m_taskPathName = a_taskPathName;
}

SchTaskExecEvent::~SchTaskExecEvent() {
}

list<string> SchTaskExecEvent::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (0 == m_evtTime)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::TIME));
	if (m_taskName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::NAME));
	if (!TskHelper::endsWith(TskHelper::toLower(m_taskName), ".job")) {
		if (m_userAccountName.empty())
			missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::USER_ID));
	}


	return missingFieldsList;
}


UserLoginEvent::UserLoginEvent(const ThreatCategory* a_cat, const string a_name) :
	ThreatEvent(a_cat, a_name, EVENT_TYPE::USER_LOGIN),
	m_srcHost(""),
	m_srcHostFQDN(""),
	m_currLoginState(LOGIN_STATE::UNKNOWN),
	m_loginType(LOGIN_TYPE::LT_UNKNOWN),
	m_loginDirection(DIRECTION::INCOMING),
	m_processPathname(""),
	m_authenitcaionPackage(""),
	m_logonProcessName("")
{

}
UserLoginEvent::~UserLoginEvent() {

}

list<string> UserLoginEvent::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (0 == m_evtTime)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::TIME));
	if (m_userAccountName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::USER_ID));

	return missingFieldsList;
}
/**
 * Set the source host name/IP for the login event.
 * Also resolve the name to FQDN and save the FQDN name.
 *
 * @param input aHost host name or ip
 * @returns void.
 */
void UserLoginEvent::setSrcHost(string& aHost) {
	m_srcHost = aHost;

	string srcHostFQDN = CyberTriageUtils::getInstance().getFQDN(m_srcHost);
	setSrcHostFQDN(srcHostFQDN);

};

string UserLoginEvent::getCurrentLoginStateStr() const {
	switch (m_currLoginState) {
	case LOGIN_STATE::UNKNOWN:
		return "unknown";
	case LOGIN_STATE::LOGGED_IN:
		return "yes";
	case LOGIN_STATE::LOGGED_OUT:
		return "no";
	default:
		return "unknown";
	}
}

bool UserLoginEvent::isSameAs(UserLoginEvent& aOtherEvent) const {

	if ((this->getType() == aOtherEvent.getType()) &&
		(0 == _stricmp(this->getUserSID().c_str(), aOtherEvent.getUserSID().c_str())) &&
		(this->getTime() == aOtherEvent.getTime())) {
		return true;
	}
	else {
		return false;
	}
}

OutgoingRDPLoginEvent::OutgoingRDPLoginEvent(const ThreatCategory* a_cat, const string a_name) :
	ThreatEvent(a_cat, a_name, EVENT_TYPE::USER_LOGIN),
	m_tgtHost(""),
	m_tgtHostFQDN(""),
	m_remoteUserName(""),
	m_remoteUserDomain(""),
	m_processPathname(""),
	m_loginType(LOGIN_TYPE::LT_REMOTE_INTERACTIVE),
	m_loginDirection(DIRECTION::OUTGOING)
{

}
OutgoingRDPLoginEvent::~OutgoingRDPLoginEvent() {

}

list<string> OutgoingRDPLoginEvent::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	//OutgoingRDPLoginEvent events are generally obtained from Registry and as such don't have a time
	//if (0 == m_evtTime)
	//	missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::TIME));

	if (m_userAccountName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::USER_ID));
	if (m_tgtHostFQDN.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_HOSTNAME));
	if (m_remoteUserName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_USER));
	if (m_remoteUserDomain.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_DOMAIN));

	return missingFieldsList;
}

/**
 * Set the target host name.
 * Also resolve the name to FQDN and save the FQDN name.
 *
 * @param input aHost host name or ip
 * @returns void.
 */
void OutgoingRDPLoginEvent::setTgtHost(string& aHost) {
	m_tgtHost = aHost;
	string tgtHostFQDN = CyberTriageUtils::getInstance().getFQDN(m_tgtHost);
	setTgtHostFQDN(tgtHostFQDN);
};


Process::Process(const ThreatCategory* a_cat, string aProcName, long aPid) :
	ThreatItem(a_cat),
	m_procName(aProcName),
	m_procId(aPid)
{
	m_pathName.clear();
	m_parentProcId = -1;
	m_creationTime = 0;
	m_isSvc = false;
	m_argsKnown = false;
}
Process::~Process() {

}

list<string> Process::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_procName.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::NAME));

	if (m_procId < 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PID));
	if (m_parentProcId < 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PPID));
	if (m_creationTime <= 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::TIME));

	if (0 != TskHelper::toLower(m_procName).compare("system")) {
		if (m_pathName.empty())
			missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PATH));
		if (m_userAccountName.empty())
			missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::USER_ID));
	}


	return missingFieldsList;
}


NetworkConnectionDescriptorBase::NetworkConnectionDescriptorBase(const ThreatCategory* a_cat, NW_CONN_DESCRIPTOR_TYPE::Enum a_descrType) :
	ThreatItem(a_cat),
	m_descriptorType(a_descrType)
{

	m_connType.clear();

	m_localIP.clear();
	m_localHostName.clear();
	m_localHostFQDN.clear();
	m_localDomain.clear();
	m_localPort = -1;

	m_remoteIP.clear();
	m_remoteHostName.clear();
	m_remoteHostFQDN.clear();
	m_remoteDomain.clear();
	m_remotePort = -1;

}

NetworkConnectionDescriptorBase:: ~NetworkConnectionDescriptorBase()
{

}
/**
 * Set the local host name/IP for the network connecion descriptor.
 * Also resolve the name to FQDN and save the FQDN name.
 *
 * @param aHostName aHost host name or ip
 * @returns void.
 */
void NetworkConnectionDescriptorBase::setLocalHostName(string & aHostName) {
	m_localHostName = aHostName;

	string localHostFQDN = CyberTriageUtils::getInstance().getFQDN(m_localHostName);
	setLocalHostFQDN(localHostFQDN);

};
/**
 * Set the remote host name/IP for the network connecion descriptor.
 * Also resolve the name to FQDN and save the FQDN name.
 *
 * @param input aHostName host name or ip
 * @returns void.
 */
void NetworkConnectionDescriptorBase::setRemoteHostName(string & aHostName) {
	m_remoteHostName = aHostName;

	string remoteHostFQDN = CyberTriageUtils::getInstance().getFQDN(m_remoteHostName);
	setRemoteHostFQDN(remoteHostFQDN);
};

ActiveNetworkConnection::ActiveNetworkConnection(const ThreatCategory* a_cat, string a_connType) :
	NetworkConnectionDescriptorBase(a_cat, NW_CONN_DESCRIPTOR_TYPE::ACTIVE_NETWORK_CONNECTION)
{

	m_connType = a_connType;

	m_connState.clear();
	m_connectionTime = 0;
	m_procId = -1;
}
ActiveNetworkConnection::~ActiveNetworkConnection() {

}

list<string> ActiveNetworkConnection::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_connState.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::STATE));
	if (0 == m_connState.compare("Listening") ||
		0 == m_connState.compare("Established")) {
		if (m_procId < 0)
			missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PID));
	}
	if (m_connectionTime <= 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::TIME));

	if (m_localPort <= 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::LOCAL_PORT));
	if (m_localIP.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::LOCAL_IP));
	if (m_localHostFQDN.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::LOCAL_HOSTNAME));

	if (m_remotePort <= 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_PORT));
	if (m_remoteIP.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_IP));
	if (m_remoteHostFQDN.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_HOSTNAME));


	return missingFieldsList;
}

ListeningPort::ListeningPort(const ThreatCategory* a_cat, string a_portType) :
	NetworkConnectionDescriptorBase(a_cat, NW_CONN_DESCRIPTOR_TYPE::LISTENING_PORT)
{
	m_connType = a_portType;
	m_procId = -1;
}
ListeningPort::~ListeningPort() {

}

list<string> ListeningPort::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	//if (m_procId < 0)			// PID isnt available for connections in TIME_WAIT state
	//	missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PID));

	if (m_openTime <= 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::TIME));

	if (m_localPort <= 0)
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::LOCAL_PORT));
	if (m_localIP.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::LOCAL_IP));
	if (m_localHostFQDN.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::LOCAL_HOSTNAME));

	return missingFieldsList;
}

DNSCacheEntry::DNSCacheEntry(const ThreatCategory* a_cat, string a_hostName) :
	ThreatItem(a_cat)
{
	setHostName(a_hostName);
}
DNSCacheEntry::~DNSCacheEntry() {

}

void DNSCacheEntry::setHostName(string &a_hostName) {
	m_hostName = a_hostName;
	string hostFQDN = CyberTriageUtils::getInstance().getFQDN(m_hostName);
	setHostFQDN(hostFQDN);
}

list<string> DNSCacheEntry::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	// we dont always get an IP, for example, from CNAME or SRV records.
	//if (m_IPs.empty())
	//	missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_IP));
	if (m_hostFQDN.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_HOSTNAME));

	return missingFieldsList;
}

ARPCacheEntry::ARPCacheEntry(const ThreatCategory* a_cat, string a_hostIP) :
	ThreatItem(a_cat),
	m_hostIP(a_hostIP)
{
	m_physAddr.clear();
}

ARPCacheEntry::~ARPCacheEntry() {

}

list<string> ARPCacheEntry::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_hostIP.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_IP));
	if (m_physAddr.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::PHYSICAL_ADDRESS));

	return missingFieldsList;
}


RoutingTableEntry::RoutingTableEntry(const ThreatCategory* a_cat, string a_hostIP) :
	ThreatItem(a_cat),
	m_hostIP(a_hostIP)
{
	m_nextHopAddr.clear();
}
RoutingTableEntry::~RoutingTableEntry() {

}

list<string> RoutingTableEntry::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_nextHopAddr.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::NEXT_HOP_ADDRESS));
	if (m_hostIP.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_IP));

	return missingFieldsList;
}


MountedDriveEntry::MountedDriveEntry(const ThreatCategory* a_cat, string a_hostName, string a_shareName) :
	NetworkConnectionDescriptorBase(a_cat, NW_CONN_DESCRIPTOR_TYPE::MOUNTED_DRIVE)
{
	setRemoteHostName(a_hostName);
	m_shareName = a_shareName;
}

MountedDriveEntry::~MountedDriveEntry() {

}

bool MountedDriveEntry::isSameAs(MountedDriveEntry& aOtherDrive) const {

	if (0 == _stricmp(this->getRemoteHostName().c_str(), aOtherDrive.getRemoteHostName().c_str()) &&
		(0 == _stricmp(this->getShareName().c_str(), aOtherDrive.getShareName().c_str())) &&
		(0 == _stricmp(this->getUserAccountName().c_str(), aOtherDrive.getUserAccountName().c_str())) &&
		(0 == _stricmp(this->getUserDomainName().c_str(), aOtherDrive.getUserDomainName().c_str()))) {
		return true;
	}
	else {
		return false;
	}
}

list<string> MountedDriveEntry::getMissingFields() const {

	list<string> missingFieldsList;
	missingFieldsList.clear();

	if (m_remoteHostFQDN.empty())
		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_HOSTNAME));

	// there are a some cases where the remote share name isn't available - say a user directly types \\servername in the Run box or in Exploer
	// if (m_shareName.empty())
	//		missingFieldsList.push_back(O_FIELD::toStr(O_FIELD::REMOTE_SHARENAME));


	return missingFieldsList;
}