/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021-2022 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Table;
import java.util.Locale;

/**
 * A utility class for handling Windows specific accounts and SIDs.
 *
 * Implementation notes:
 * - SIDs for standard "Service Accounts" are added to a host-scoped special realm. 
 * - SIDs for standard groups are not added as OS Accounts
 * 
 */
final class WindowsAccountUtils {
	

	final static String SPECIAL_WINDOWS_BACK_UP_POSTFIX = ".bak";
	
	// Windows sometimes uses a special NULL sid, when a users actual SID is unknown.
	// Our SID comparisons should ignore it, and treat it as a null/blank. 
	final static String WINDOWS_NULL_SID = "S-1-0-0";
	
	// Windows uses SIDs for groups as well as users. 
	// We dont want to create "User" account for group SIDs.
	// The lists here help us identify and weed out group SIDs when creating accounts.
	private static final Set<String> GROUP_SIDS = ImmutableSet.of(
			"S-1-1-0",	// Everyone
			"S-1-2-0",	// Local - anyone who has logged on locally
			"S-1-2-1",	// Console Logon
			
			"S-1-3-1",	// Creator
			"S-1-3-4",	// Owner rights
			
			"S-1-5-1",	// Dialup
			"S-1-5-2",	// Network
			"S-1-5-3",	// Batch
			"S-1-5-4",	// Interactive
			"S-1-5-6",	// Service
			"S-1-5-7",	// Anonymous
			"S-1-5-9",	// Enterprise Domain Controllers
			
			"S-1-5-11",	// Authenticated Users
			"S-1-5-12",	// Restricted Code - not a group but not a user SID either
			"S-1-5-13",	// Terminal Server Users
			"S-1-5-14",	// Remote Interactive Logon
			
			"S-1-5-15",	// This Organization
			
			"S-1-5-80-0",	// All Services
			"S-1-5-83-0",	// NT Virtual Machine\Virtual Machines
			"S-1-5-90-0"	// Windows Manager\Windows Manager Group
				
	);
	
	// Any SIDs with the following prefixes are group SID and should be excluded.
	private static final Set<String> GROUP_SID_PREFIX = ImmutableSet.of(
			"S-1-5-32",		// Builtin
			"S-1-5-87"		// Task ID prefix
			
	);
	
	// SIDS that begin with a domain SID prefix and have on of these 
	private static final String NTAUTHORITY_SID_PREFIX = "S-1-5";	
	private static final String NTAUTHORITY_REALM_NAME = "NT AUTHORITY";
	
	
	private static final Set<String> DOMAIN_GROUP_SID_SUFFIX = ImmutableSet.of(
			"-512",		// Domain Admins
			"-513",		// Domain Users
			
			"-514",		// Domain Guests
			"-515",		// Domain Computers	
			"-516",		// Domain Controllers
			"-517",		// Cert Publishers
			
			"-518",		// Schema Admins
			"-519",		// Enterprise Admins
			"-520",		// Group Policy Creator Owners
			
			"-526",		// Key Admins
			"-527",		// Enterprise Key Admins
			
			"-533",		// RAS and IAS Servers
			
			// Windows 2008 and later
			"-498",		// Enterprise Read-only Domain Controllers
			"-521",		// Read-only Domain Controllers
			"-571",		// Allowed RODC Password Replication Group
			"-572",		// Denied RODC Password Replication Group
			
			// Windows 2012 and later
			"-522"		// Cloneable Domain Controllers
	);
	
	
	/**
	 * This encapsulates a WellKnown windows SID. 
	 * 
	 */
	public static class WellKnownSidInfo {

		WellKnownSidInfo(boolean isUserSID, String addr, String realmName, String loginName, String description) {
			this.realmAddr = addr;
			this.isUserSID = isUserSID;
			this.realmName = realmName;
			this.loginName =  this.isUserSID ? loginName : "";
			this.description = description;
		}
		
		private final String realmAddr;		// realm identifier - S-1-5-18
		private final boolean isUserSID;	// is this a realm SID or a user SID
		private final String realmName;		// realm name 
		private final String loginName;		// user login name, may be empty
		private final String description;	// description 

		public String getRealmAddr() {
			return realmAddr;
		}

		public boolean isIsUserSID() {
			return isUserSID;
		}

		public String getRealmName() {
			return realmName;
		}

		public String getLoginName() {
			return loginName;
		}

		public String getDescription() {
			return description;
		}
		
		
	}
	
	// These windows SID indicate well known windows accounts.
	// Well known SIDs and account are handled slightly differently from the regular accounts:
	//  - We can assume and fill in SID from given account name, and vice versa.
	//  - We map account names in foreign languages (some known set) to english names, for these well known accounts. 
	private static final Map<String, WellKnownSidInfo> SPECIAL_SIDS_MAP =  ImmutableMap.<String, WellKnownSidInfo>builder() 
			.put("S-1-5-17", new WellKnownSidInfo(true, "S-1-5", NTAUTHORITY_REALM_NAME, "IUSR", "IIS Default Account"))			
			.put("S-1-5-18", new WellKnownSidInfo(true, "S-1-5", NTAUTHORITY_REALM_NAME, "SYSTEM", "Local System Account"))
			.put("S-1-5-19", new WellKnownSidInfo(true, "S-1-5", NTAUTHORITY_REALM_NAME, "LOCAL SERVICE", "Local Service Account"))
			.put("S-1-5-20", new WellKnownSidInfo(true, "S-1-5", NTAUTHORITY_REALM_NAME, "NETWORK SERVICE", "Network Service Account"))
			.build();
		

	// These SID prefixes indicate well known windows accounts.
	//  - We can fill in the login names for these SID, as well as account user description.
	private static final Map<String, WellKnownSidInfo> SPECIAL_SID_PREFIXES_MAP = ImmutableMap.<String, WellKnownSidInfo>builder() 
			.put("S-1-5-80", new WellKnownSidInfo(false, "S-1-5-80", "NT SERVICE", "", "NT Service Virtual Account"))
			.put("S-1-5-82", new WellKnownSidInfo(false, "S-1-5-82", "IIS APPPOOL", "", "IIS AppPool Virtual Account"))
			.put("S-1-5-83", new WellKnownSidInfo(false, "S-1-5-83", "NT VIRTUAL MACHINE", "", "Virtual Machine Virtual Account") )
			.put("S-1-5-90", new WellKnownSidInfo(false, "S-1-5-90", "Window Manager", "", "Windows Manager Virtual Account"))
			.put("S-1-5-94", new WellKnownSidInfo(false, "S-1-5-94", "WinRM Virtual Users", "", "Windows Remoting Virtual Account"))
			.put("S-1-5-96",  new WellKnownSidInfo(false, "S-1-5-96", "Font Driver Host", "", "Font Driver Host Virtual Account"))
			.build();
			
	
	// Looks for security identifier prefixes of the form S-<number>-<number>-<number>
	// More information on security identifier architecture can be found at: 
	// https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers
	// A number of accounts in the range S-1-5-80-* to S-1-5-111-* are special. 
	private static final Pattern WINDOWS_SPECIAL_ACCOUNT_PREFIX_REGEX = Pattern.compile("^[sS]\\-1\\-5\\-(\\d+)\\-");
	
			
	// This map reverse maps some of the Well know account names (realm name &login name) to their well known SIDs. 
	private static final Table<String, String, String> SPECIAL_ACCOUNTS_TO_SID_MAP = HashBasedTable.create();
	static {
		SPECIAL_ACCOUNTS_TO_SID_MAP.put(NTAUTHORITY_REALM_NAME, "SYSTEM", "S-1-5-18");
		SPECIAL_ACCOUNTS_TO_SID_MAP.put(NTAUTHORITY_REALM_NAME, "LOCAL SERVICE", "S-1-5-19");
		SPECIAL_ACCOUNTS_TO_SID_MAP.put(NTAUTHORITY_REALM_NAME, "NETWORK SERVICE", "S-1-5-20");
	}
	
	// A mapping of various well known realm names to their English names.  
	// We store only english names in the database for well known SIDs.  
	// Input names provided by client are first mapped to english before lookup or insert. 
	private static final Map<String, String> REALM_NAME_TO_ENGLISH_MAP =  ImmutableMap.<String, String>builder() 
			.put("NT AUTHORITY", NTAUTHORITY_REALM_NAME)	// to facilitate a quick hit on the english name
			.put("NT-AUTORITÄT", NTAUTHORITY_REALM_NAME)
			.put("AUTORITE NT", NTAUTHORITY_REALM_NAME)
			.put("NT INSTANS", NTAUTHORITY_REALM_NAME)
			.build();

	// A mapping of various well known realm names to their English names.  
	// We store only english names in the database for well known SIDs.  
	// Input names provided by client are first mapped to english before lookup or insert. 
	private static final Map<String, String> LOGINNAME_TO_ENGLISH_MAP =  ImmutableMap.<String, String>builder() 
			.put("SYSTEM", "SYSTEM")	// to facilitate a quick hit on the english name
			.put("SYSTÈME", "SYSTEM")
			
			.put("LOCAL SERVICE", "LOCAL SERVICE")
			.put("LOKALER DIENST", "LOCAL SERVICE")
			.put("SERVICE LOCAL", "LOCAL SERVICE")
			.put("SERVIZIO LOCALE", "LOCAL SERVICE")
			.put("SERVICIO LOC", "LOCAL SERVICE")
			
			.put("NETWORK SERVICE", "NETWORK SERVICE")
			.put("NETZWERKDIENST", "NETWORK SERVICE")
			.put("NÄTVERKSTJÄNST", "NETWORK SERVICE")
			.put("SERVICE RÉSEAU", "NETWORK SERVICE")
			.put("SERVIZIO DI RETE", "NETWORK SERVICE")
			.put("SERVICIO DE RED", "NETWORK SERVICE")
			.build();
	
	/**
	 * Checks if the given SID is a well known Windows SID.
	 * 
	 * @param sid SID to check.
	 * 
	 * @return True if the SID is a Windows well known SID, false otherwise 
	 */
	static boolean isWindowsWellKnownSid(String sid) {
		
		String tempSID = stripWindowsBackupPostfix(sid);
		if (SPECIAL_SIDS_MAP.containsKey(tempSID)) {
			return true;
		}
		for (String specialPrefix: SPECIAL_SID_PREFIXES_MAP.keySet()) {
			if (tempSID.startsWith(specialPrefix)) {
				return true;
			}
		}
		
		Matcher match = WINDOWS_SPECIAL_ACCOUNT_PREFIX_REGEX.matcher(tempSID);
		if (match.find()) {
			Integer domainIdentifier = Integer.valueOf(match.group(1));
			// All the prefixes in the range S-1-5-80 to S-1-5-111 are special
			if (domainIdentifier != null && domainIdentifier >= 80 && domainIdentifier <= 111) {
				return true;
			}
		}
		
		return false;
	}
	
	/**
	 * Checks if the given realmName/loginName is a well known account..
	 * 
	 * @param sid SID to check.
	 * 
	 * @return True if the SID is a Windows well known SID, false otherwise 
	 */
	static boolean isWindowsWellKnownAccountName(String loginName, String realmName) {
		
		String resolvedRealmName = toWellknownEnglishRealmName(realmName);
		String resolvedLoginName = toWellknownEnglishLoginName(loginName);
		if (StringUtils.isBlank(resolvedRealmName) ||  StringUtils.isBlank(resolvedLoginName)) {
			return false;
		}
		
		return SPECIAL_ACCOUNTS_TO_SID_MAP.contains(resolvedRealmName.toUpperCase(), resolvedLoginName.toUpperCase());
		
	}
	
	/**
	 * Get the realm address for the given well known Windows SID.
	 * 
	 * @param sid SID to check.
	 * @return Realm Name for Windows special SID, an empty string if the SID is not a known special SID. 
	 * 
	 * @throws TskCoreException 
	 */
	private static String getWindowsWellKnownSidRealmAddr(String sid) throws TskCoreException {
		String tempSID = stripWindowsBackupPostfix(sid);

		if (SPECIAL_SIDS_MAP.containsKey(tempSID)) {
			return SPECIAL_SIDS_MAP.get(tempSID).getRealmAddr();
		}
		
		for (Entry<String, WellKnownSidInfo> specialPrefixEntry : SPECIAL_SID_PREFIXES_MAP.entrySet()) {
			if (tempSID.startsWith(specialPrefixEntry.getKey())) {
				return specialPrefixEntry.getValue().getRealmAddr();
			}
		}

		Matcher match = WINDOWS_SPECIAL_ACCOUNT_PREFIX_REGEX.matcher(tempSID);
		if (match.find()) {
			Integer domainIdentifier = Integer.valueOf(match.group(1));
			// All the prefixes in the range S-1-5-80 to S-1-5-111 are special
			if (domainIdentifier != null && domainIdentifier >= 80 && domainIdentifier <= 111) {
				String realmAddr = String.format("%s-%d", NTAUTHORITY_SID_PREFIX, domainIdentifier);
				return realmAddr;
			}
		}
		
		return "";
	}
	/**
	 * Get the well known SID info for the given SID. 
	 * 
	 * @param sid SID to check.
	 * 
	 * @return WellKnownSidInfo for the SID, null if there is no info available. 
	 */
	private static WellKnownSidInfo getWindowsWellKnownInfo(String sid) {
		String tempSID = stripWindowsBackupPostfix(sid);
		
		if (SPECIAL_SIDS_MAP.containsKey(tempSID)) {
			return SPECIAL_SIDS_MAP.get(tempSID);
		}
		for (Entry<String, WellKnownSidInfo> specialPrefixEntry: SPECIAL_SID_PREFIXES_MAP.entrySet()) {
			if (tempSID.startsWith(specialPrefixEntry.getKey())) {
				return specialPrefixEntry.getValue();
			}
		}
		return null;
	}
	
	/**
	 * Get the realm address for the given special Windows SID.
	 * 
	 * @param sid SID to check.
	 * 
	 * @return Name for Windows special SID, an empty string if the SID is not a known special SID. 
	 */
	static String getWindowsWellKnownSidFullName(String sid) {
		WellKnownSidInfo wellKnownSidInfo = getWindowsWellKnownInfo(sid);
		return Objects.nonNull(wellKnownSidInfo) ? wellKnownSidInfo.getDescription() : "";
	}
	
	/**
	 * Get the realm name for the given well known Windows SID.
	 * 
	 * @param sid SID to check.
	 * 
	 * @return Realm Name for Windows special SID, NULL if the SID is not a known special SID. 
	 */
	static String getWindowsWellKnownSidRealmName(String sid) {
		
		if (StringUtils.isNotBlank(sid) && sid.equals(NTAUTHORITY_SID_PREFIX)) {
			return NTAUTHORITY_REALM_NAME;
		}
		
		WellKnownSidInfo wellKnownSidInfo = getWindowsWellKnownInfo(sid);
		return Objects.nonNull(wellKnownSidInfo) 
				? wellKnownSidInfo.getRealmName() 
				: null;
	}
	
	/**
	 * Get the login name for the given well known Windows SID.
	 * 
	 * @param sid SID to check.
	 * 
	 * @return Login Name for Windows special SID, NULL if the SID is not a known special SID. 
	 */
	static String getWindowsWellKnownSidLoginName(String sid) {
		
		WellKnownSidInfo wellKnownSidInfo = getWindowsWellKnownInfo(sid);
		return Objects.nonNull(wellKnownSidInfo) 
				? wellKnownSidInfo.getLoginName()
				: null;
	}
	
	
	/**
	 * Returns the SID for a well known account name.
	 * 
	 * @param loginName Well known login name.
	 * @param realmName Well known realm name. 
	 * 
	 * @return SID corresponding to the well known account name, NULL if its not known. 
	 */
	static String getWindowsWellKnownAccountSid( String loginName, String realmName) {
		
		String resolvedRealmName = toWellknownEnglishRealmName(realmName);
		String resolvedLoginName = toWellknownEnglishLoginName(loginName);
		if (StringUtils.isBlank(resolvedRealmName) ||  StringUtils.isBlank(resolvedLoginName)) {
			return null;
		}
		
		return SPECIAL_ACCOUNTS_TO_SID_MAP.get(resolvedRealmName.toUpperCase(), resolvedLoginName.toUpperCase());
		
	}
	
	/**
	 * Returns english name for a given well known realm name.
	 *
	 * @param name Realm name to translate.
	 *
	 * @return English realm name corresponding to given realm name, NULL if
	 *         realm name is not known.
	 */
	static String toWellknownEnglishRealmName(String name) {
		return StringUtils.isNotBlank(name)
				? REALM_NAME_TO_ENGLISH_MAP.getOrDefault(name.toUpperCase(), name)
				: null;
	}

	/**
	 * Returns english name for the given well known login name.
	 *
	 * @param name Login name to translate.
	 *
	 * @return English login name corresponding to given login name. NULL if
	 *         login name is not known.
	 */
	static String toWellknownEnglishLoginName(String name) {
		return StringUtils.isNotBlank(name)
				? LOGINNAME_TO_ENGLISH_MAP.getOrDefault(name.toUpperCase(), name)
				: null;
	}
		
	/**
	 * Checks if the given SID is a user SID.
	 * 
	 * If the given SID is not found among the known group SIDs, is considered a user SID.
	 * 
	 * @param sid SID to check.
	 * 
	 * @return True if the SID is a user SID, false otherwise 
	 */
	static boolean isWindowsUserSid(String sid) {
		
		String tempSID = stripWindowsBackupPostfix(sid);
		
		if (GROUP_SIDS.contains(tempSID)) {
			return false;
		}
		
		for (String prefix: GROUP_SID_PREFIX) {
			if (tempSID.startsWith(prefix)) {
				return false;
			}
		}
		
		// check for domain groups - they have a domains specific identifier but have a fixed prefix and suffix
		if (tempSID.startsWith(NTAUTHORITY_SID_PREFIX)) {
			for (String suffix : DOMAIN_GROUP_SID_SUFFIX) {
				if (tempSID.endsWith(suffix)) {
					return false;
				}
			}
		}
		
		return true;
		
	}
	
	/**
	 * Get the windows realm address from the given SID.
	 *
	 * For all regular account SIDs, the realm address is the sub-authority SID.
	 * For some well known accounts, the realm address is returned from a
	 * predetermined list.
	 *
	 * @param sid SID
	 *
	 * @return Realm address for the SID.
	 *
	 * @throws TskCoreException If the given SID is not a valid host/domain SID.
	 */
	public static String getWindowsRealmAddress(String sid) throws TskCoreException {
		
		String realmAddr;
		String tempSID = stripWindowsBackupPostfix(sid);
		
		if ( isWindowsWellKnownSid(tempSID)) {
			realmAddr = getWindowsWellKnownSidRealmAddr(sid);
		} else {
			// SIDs should have at least 4 components: S-1-A-S
			// A: authority identifier
			// S: one or more sub-authority identifiers (RIDs)
			if (org.apache.commons.lang3.StringUtils.countMatches(tempSID, "-") < 3) {
				throw new TskCoreException(String.format("Invalid SID %s for a host/domain", tempSID));
			}
			// get the sub authority SID
			realmAddr = sid.substring(0, tempSID.lastIndexOf('-'));
		}

		return realmAddr;
	}
	
	/**
	 * Backup windows sid will include the postfix .bak on the end of the sid.
	 * Remove the postfix for easier processing.
	 * 
	 * @param sid 
	 * 
	 * @return The sid with the postfix removed.
	 */
	private static String stripWindowsBackupPostfix(String sid) {
		String tempSID = sid;
		
		if(tempSID.endsWith(SPECIAL_WINDOWS_BACK_UP_POSTFIX)) {
			tempSID = tempSID.replace(SPECIAL_WINDOWS_BACK_UP_POSTFIX, "");
		}
		
		return tempSID;
	}
	
}
