/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.EmailValidator;

/**
 * Provides general utility methods related to communications artifacts.
 * 
 */
public final class CommunicationsUtils {
	
	/**
     * Empty private constructor.
     */
    private CommunicationsUtils() {
    }
	
	/**
	 * Normalize the given phone number by removing all non numeric characters, 
	 * except for a leading +.
	 *
	 * @param phoneNum The string to normalize.
	 *
	 * @return The normalized phone number.
	 * 
	 * @throws TskCoreException If the given string is not a valid phone number.
	 * 
	 */
	public static String normalizePhoneNum(String phoneNum) throws TskCoreException {
		if (phoneNum.matches("\\+?[0-9()\\-\\s]+")) {
           return phoneNum.replaceAll("[^0-9\\+]", "");
        } else {
            throw new TskCoreException(String.format("Input string is not a valid phone number: %s", phoneNum));
        }	
	}

	/**
	 * Normalizes the given email address by converting it to lowercase.
	 *
	 * @param emailAddress The email address string to be normalized.
	 *
	 * @return The normalized email address.
	 * @throws TskCoreException If the given string is not a valid email address.
	 */
	public static String normalizeEmailAddress(String emailAddress) throws TskCoreException {
		
        if (isValidEmailAddress(emailAddress)) {
            return emailAddress.toLowerCase();
        } else {
            throw new TskCoreException(String.format("Input string is not a valid email address: %s", emailAddress));
        }
	}
	
	/**
	 * Checks if the given accountId is a valid id for 
	 * the specified account type.
	 * 
	 * @param accountType Account type.
	 * @param accountUniqueID Id to check.
	 * 
	 * @return True, if the id is a valid id for the given account type, False otherwise.
	 */
	public static boolean isValidAccountId(Account.Type accountType, String accountUniqueID) {
		if (accountType == Account.Type.PHONE) {
			return isValidPhoneNumber(accountUniqueID);
		}
		if (accountType == Account.Type.EMAIL) {
			return isValidPhoneNumber(accountUniqueID);
		}
		
		return !StringUtils.isEmpty(accountUniqueID);
	}
	
	/**
	 * Checks if the given string is a valid phone number.
	 *
	 * @param phoneNum Phone number string to check.
	 *
	 * @return True if the given string is a valid phone number, false otherwise.
	 */
	public static boolean isValidPhoneNumber(String phoneNum) {
		if (!StringUtils.isEmpty(phoneNum)) {
			return phoneNum.matches("\\+?[0-9()\\-\\s]+");
		}
		return false;
	}
	
	/**
	 * Checks if the given string is a valid email address.
	 *
	 * @param emailAddress String to check.
	 *
	 * @return True if the given string is a valid email address, false otherwise.
	 */
	public static boolean isValidEmailAddress(String emailAddress) {
		if (!StringUtils.isEmpty(emailAddress)) {
			EmailValidator validator = EmailValidator.getInstance(true, true);
			return validator.isValid(emailAddress);
		}

		return false;
	}
}
