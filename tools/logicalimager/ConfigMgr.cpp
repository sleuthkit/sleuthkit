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

#include <windows.h>
#include <iostream>
#include <direct.h>
#include <sys/stat.h>

#include "ConfigMgr.h"
#include "TskHelper.h"

const int DEFAULT_SERVER_PORT = 80;
const int DEFAULT_SERVER_REST_PORT = 8080;

ConfigMgr::ConfigMgr()
{
	m_targetComputerName.clear();

	m_imageName.clear();
	m_inputPathName.clear();
	m_tempOutDirPath.clear();
	m_targetComputerName.clear();

	m_isLiveSystem = false;
	m_reportFileContents = true;   // true by default
	m_isRegressionTestMode = false;
	m_saveTempFiles = false;       // false by default

	m_reportOnlySuspStartupProgs = false;  // false by default
	m_showCounters = false;
	m_printDebugMsgs = false;
	m_dummyAgentMode = false;

	m_sendDataOverNetwork = false;
	m_uiServerHost.clear();
	m_uiServerHostList.clear();
	m_uiServerPortNum = DEFAULT_SERVER_PORT;
	m_sessionID.clear();

	m_agentVersion = "Unknown";
	m_agentExePath.clear();

	setWinNTVersion();
	findAgentExePath();
}

ConfigMgr::~ConfigMgr()
{
}

void ConfigMgr::setWinNTVersion() {
	OSVERSIONINFO	vi;
	memset(&vi, 0, sizeof vi);
	vi.dwOSVersionInfoSize = sizeof vi;
	GetVersionEx(&vi);

	m_winntVerMajor = vi.dwMajorVersion;
	m_winntVerMinor = vi.dwMinorVersion;
}


/* NOTES:
 * https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx
 * 5.1: XP 32-bit
 * 5.2: XP 64-bit
 * 6.0: Vista
 * 6.1: Windows 7
 * 6.2: Windows 8
 * 6.3: Windows 8.1
 * 10.0: Windows 10
 */



void ConfigMgr::getWinNTVersion(unsigned int &a_verMajor, unsigned int & a_verMinor) {
	a_verMajor = m_winntVerMajor;
	a_verMinor = m_winntVerMinor;
}

// is Windows NT 6.2 or higher?
bool ConfigMgr::isWinNT62() {
	return((m_winntVerMajor == 6) && (m_winntVerMinor >= 2));
}

// is Windows XP or older?
bool ConfigMgr::isWinXPOrOlder() {
	return((m_winntVerMajor <= 5));
}



void ConfigMgr::findAgentExePath() {
	wchar_t exePath[MAX_PATH];
	memset(exePath, 0, sizeof(exePath));

	// get own exe pathname
	if (!GetModuleFileName(NULL, exePath, MAX_PATH)) {
		cerr << "GetModuleFileName() failed to return agent exe path" << endl;
		return;
	}

	// split path & exe name
	wstring wsEXEPath(exePath);
	size_t pos = wsEXEPath.rfind(L'\\');
	if (pos != wstring::npos) {
		m_agentExeName = wsEXEPath.substr(pos + 1);
		wsEXEPath.erase(pos + 1);
	}

	m_agentExePath = wsEXEPath;

	// Agent may be named xyz.exe or xyz_nolibs.exe, in both cases the effective name is xyz
	m_agentEffectiveName = m_agentExeName;
	pos = TskHelper::toLower(TskHelper::toNarrow(m_agentExeName)).rfind("_nolibs");
	if (pos != wstring::npos) {
		pos = m_agentExeName.rfind(L"_");
		m_agentEffectiveName.erase(pos, wstring(L"_NoLibs").length());
	}

	pos = TskHelper::toLower(TskHelper::toNarrow(m_agentEffectiveName)).rfind(".exe");
	if (pos != wstring::npos) {
		pos = m_agentEffectiveName.rfind(L".");
		m_agentEffectiveName.erase(pos, wstring(L".exe").length());
	}
}

int ConfigMgr::makeTempOutDir() {

	int ret = 0;
	time_t now;
	struct tm localTime;
	time(&now);
	gmtime_s(&localTime, &now);

	char timeStr[32];
	strftime(timeStr, sizeof timeStr, "%Y%m%d_%H_%M_%S", &localTime);

	// create the temp output dir wherever the agent exe is. 
	// If the agent is run from USB drive then we can avoid leaving any traces or overwriting any unalloc data
	string rootFolder = TskHelper::toNarrow(getAgentExePath());

	string outDirName;
	if (m_isLiveSystem) { // if analyzing a live system , create the temp folder where the EXE lives, to minimize any alterations to system under test.
		outDirName = "CTT_" + string(timeStr);
		rootFolder = TskHelper::toNarrow(getAgentExePath());
	}
	else { // if analyzing an image, create the temp folder in C:\Windows\Temp, usualy we won't have access to create the folder in C:\Program Files .....
		outDirName = m_imageName + "_" + string(timeStr);
		TCHAR lpTempPathBuffer[MAX_PATH];
		GetTempPath(MAX_PATH, lpTempPathBuffer);
		rootFolder = TskHelper::toNarrow(wstring(lpTempPathBuffer));
	}

	m_tempOutDirPath = rootFolder + "\\" + outDirName;

	struct stat st;
	if (stat(m_tempOutDirPath.c_str(), &st) != 0)
	{
		int rc = _mkdir(m_tempOutDirPath.c_str());
		if (rc != 0) {
			cerr << "makeTempOutDir(): Failed to create temp output folder = " << m_tempOutDirPath << " Error: " << GetLastError() << endl;
			ret = -1;
		}
	}

	return ret;

}

void ConfigMgr::rmTempOutDir() {
	int rc;
	if (!m_saveTempFiles) {
		if (0 != (rc = _rmdir(m_tempOutDirPath.c_str())))
			cerr << "rmTempOutDir(): Failed to delete temp output folder = " << m_tempOutDirPath << " Error: " << rc << endl;
	}
}
