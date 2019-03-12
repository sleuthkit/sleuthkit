/*
 ** tsk_logical_imager
 ** The Sleuth Kit 
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2011 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

#include <direct.h>
#include <winsock2.h>
#include "tsk/tsk_tools_i.h"
#include "tsk/auto/tsk_case_db.h"
#include "tsk/img/img_writer.h"
#include <locale.h>

static TSK_TCHAR *progname;

static void
usage()
{
    TFPRINTF(stderr,
        _TSK_T
        ("usage: %s [-i imgtype] \n"),
        progname);
    tsk_fprintf(stderr,
        "\t-i imgPath: The image file\n");
	tsk_fprintf(stderr, "\t-v: verbose output to stderr\n");
	tsk_fprintf(stderr, "\t-V: Print version\n");
    exit(1);
}

// is Windows XP or older?
bool isWinXPOrOlder() {
	OSVERSIONINFO	vi;
	memset(&vi, 0, sizeof vi);
	vi.dwOSVersionInfoSize = sizeof vi;
	GetVersionEx(&vi);
	unsigned int m_winntVerMajor = vi.dwMajorVersion;
	unsigned int m_winntVerMinor = vi.dwMinorVersion;

	return((m_winntVerMajor <= 5));
}

static BOOL IsProcessElevated() {
	static BOOL fRet = FALSE;
	HANDLE hToken = NULL;

	// the below logic doesn't work on XP, so lie and say
	// yes.  It will eventually fail with an uglier message
	// is Windows XP or older?
	if (isWinXPOrOlder()) {
		return TRUE;
	}

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
		TOKEN_ELEVATION Elevation;
		DWORD cbSize = sizeof(TOKEN_ELEVATION);
		if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
			fRet = Elevation.TokenIsElevated;
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return fRet;
}

int getLocalHost(string &a_hostName) {

	// Initialize Winsock
	WSADATA wsaData;
	int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		fprintf(stderr, "WSAStartup failed with error = %d\n", iResult);
		return -1;
	}

	char buf[MAX_PATH];
	if (gethostname(buf, sizeof(buf)) == SOCKET_ERROR) {
		fprintf(stderr, "Error getting host name. Error =  %d\n", WSAGetLastError());
		return -1;
	}
	a_hostName = string(buf);

	WSACleanup();
	return 0;
}

int createDirectory(string &directoryPathname) {
	time_t now;
	struct tm localTime;

	time(&now);
	gmtime_s(&localTime, &now);

	char timeStr[32];
	strftime(timeStr, sizeof timeStr, "%Y%m%d_%H_%M_%S", &localTime);

	string outDirName;
	string hostName;
	if (0 == getLocalHost(hostName)) {
		outDirName = "Logical_Imager_" + hostName + "_" + timeStr;
	}

	struct stat st;
	if (stat(outDirName.c_str(), &st) != 0)
	{
		int rc = _mkdir(outDirName.c_str());
		if (rc != 0) {
			fprintf(stderr, "Failed to create output folder = %s Error: %d\n", outDirName.c_str(), rc);
			return -1;
		}
	}
	directoryPathname = outDirName;
	return 0;
}

int
main(int argc, char **argv1)
{
	TSK_IMG_INFO *img;
	TSK_IMG_TYPE_ENUM imgtype = TSK_IMG_TYPE_DETECT;

	int ch;
	TSK_TCHAR **argv;
	unsigned int ssize = 0;
	TSK_TCHAR *imgPath[1];
	BOOL iFlagUsed = FALSE;

#ifdef TSK_WIN32
	// On Windows, get the wide arguments (mingw doesn't support wmain)
	argv = CommandLineToArgvW(GetCommandLineW(), &argc);
	if (argv == NULL) {
		fprintf(stderr, "Error getting wide arguments\n");
		exit(1);
	}
#else
	argv = (TSK_TCHAR **)argv1;
#endif
	progname = argv[0];
	setlocale(LC_ALL, "");

	while ((ch = GETOPT(argc, argv, _TSK_T("i:vV"))) > 0) {
		switch (ch) {
		case _TSK_T('?'):
		default:
			TFPRINTF(stderr, _TSK_T("Invalid argument: %s\n"),
				argv[OPTIND]);
			usage();

		case _TSK_T('v'):
			tsk_verbose++;
			break;

		case _TSK_T('V'):
			tsk_version_print(stdout);
			exit(0);

		case _TSK_T('i'):
			imgPath[0] = OPTARG;
			iFlagUsed = TRUE;
			break;
		}
	}

	if (!iFlagUsed) {
		if (!IsProcessElevated()) {
			fprintf(stderr, "Process is not running in elevated mode\n");
			exit(1);
		}
	}

	// create a directory with hostname_timestamp
	string directory_path;
	if (createDirectory(directory_path) == -1) {
		exit(1);
	}
	fprintf(stdout, "Created directory %s", directory_path.c_str());

	if ((img = tsk_img_open(1, imgPath, imgtype, ssize)) == NULL) {
		tsk_error_print(stderr);
		exit(1);
	}

	string outputFileName = directory_path + "/sparse_image.vhd";
	int ilen = outputFileName.size();
	TCHAR *outputFileNameW = (TCHAR *)tsk_malloc((ilen + 1) * sizeof(TCHAR));
	if (outputFileNameW == NULL) {
		fprintf(stderr, "tsk_malloc returns NULL\n");
		exit(1);
	}
	UTF8 *utf8 = (UTF8 *)outputFileName.c_str();
	UTF16 *utf16 = (UTF16 *)outputFileNameW;

	int retval =
		tsk_UTF8toUTF16((const UTF8 **)&utf8, &utf8[ilen],
			&utf16, &utf16[ilen], TSKlenientConversion);

	if (tsk_img_writer_create(img, outputFileNameW) == TSK_ERR) {
		fprintf(stderr, "tsk_img_writer_create returns TSK_ERR\n");
		exit(1);
	}

	if (tsk_img_writer_finish(img) == TSK_ERR) {
		fprintf(stderr, "tsk_img_writer_finish returns TSK_ERR\n");
		// not exiting, should call tsk_img_close.
	}

	tsk_img_close(img);
    exit(0);
}
