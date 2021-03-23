/**
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
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

import com.google.common.collect.ImmutableSet;
import java.util.Set;

/**
 * A utility class for handling Windows specific accounts and SIDs.
 * 
 */
final class WindowsAccountUtils {
	
	// Special Windows Accounts with short SIDS are given a special realm "address".
	final static String SPECIAL_WINDOWS_REALM_ADDR = "SPECIAL_WINDOWS_ACCOUNTS";
	
	
	// Windows uses SIDs for groups as well as users. 
	// We dont want to create "User" account for group SIDs.
	// The lists here help us identify and weed out group SIDs when creating accounts.
	private static final Set<String> GROUP_SIDS = ImmutableSet.of(
			"S-1-0-0",	// Null SID
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
			"S-1-5-32"		// Builtin
			
	);
	
	// SIDS that begin with a domain SID prefix and have on of these 
	private static final String DOMAIN_SID_PREFIX = "S-1-5";	
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
	
	
	
	// Some windows SID indicate special account.
	// These should be handled differently from regular user accounts.
	private static final Set<String> SPECIAL_SIDS = ImmutableSet.of(
			"S-1-5-18",	// LOCAL_SYSTEM_ACCOUNT
			"S-1-5-19", // LOCAL_SERVICE_ACCOUNT
			"S-1-5-20" // NETWORK_SERVICE_ACCOUNT
	);
	private static final Set<String> SPECIAL_SID_PREFIXES = ImmutableSet.of(
			"S-1-5-80",	// Virtual Service accounts
			"S-1-5-82", // AppPoolIdentity Virtual accounts. 
			"S-1-5-83", // Virtual Machine  Virtual Accounts.
			"S-1-5-90", // Windows Manager Virtual Accounts. 
			"S-1-5-96" // Font Drive Host Virtual Accounts.
			);
	
	
	/**
	 * Checks if the given SID is a special Windows SID.
	 * 
	 * @param sid SID to check.
	 * 
	 * @return True if the SID is a Windows special SID, false otherwise 
	 */
	static boolean isWindowsSpecialSid(String sid) {
		if (SPECIAL_SIDS.contains(sid)) {
			return true;
		}
		for (String specialPrefix: SPECIAL_SID_PREFIXES) {
			if (sid.startsWith(specialPrefix)) {
				return true;
			}
		}
		return false;
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
		
		if (GROUP_SIDS.contains(sid)) {
			return false;
		}
		
		for (String prefix: GROUP_SID_PREFIX) {
			if (sid.startsWith(prefix)) {
				return false;
			}
		}
		
		// check for domain groups - they have a domains specific identifier but have a fixed prefix and suffix
		if (sid.startsWith(DOMAIN_SID_PREFIX)) {
			for (String suffix : DOMAIN_GROUP_SID_SUFFIX) {
				if (sid.endsWith(suffix)) {
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
	 * For special Windows account the realm address is a special address, 
	 * SPECIAL_WINDOWS_REALM_ADDR { @link WindowsAccountUtils.SPECIAL_WINDOWS_REALM_ADDR}
	 * 
	 * @param sid SID
	 * 
	 * @return Realm address for the SID.
	 * 
	 * @throws TskCoreException If the given SID is not a valid host/domain SID.
	 */
	public static String getWindowsRealmAddress(String sid) throws TskCoreException {
		
		String realmAddr;
		
		if (isWindowsSpecialSid(sid)) {
			realmAddr = SPECIAL_WINDOWS_REALM_ADDR;
		} else {
			// regular SIDs should have at least 5 components: S-1-x-y-z
			if (org.apache.commons.lang3.StringUtils.countMatches(sid, "-") < 4) {
				throw new TskCoreException(String.format("Invalid SID %s for a host/domain", sid));
			}
			// get the sub authority SID
			realmAddr = sid.substring(0, sid.lastIndexOf('-'));
		}

		return realmAddr;
	}
	
}
