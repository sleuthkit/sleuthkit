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
	 * Checks if the given string may be a phone number.
	 * Normalize the phone number by removing all non numeric characters, except
	 * for leading +.
	 *
	 * @param phoneNum The string to check and normalize.
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
	 * Checks if the given string is a valid email address.
	 * Normalizes the given email address by converting it to lowercase.
	 *
	 * @param emailAddress The string to be checked and normalized.
	 *
	 * @return The normalized email address.
	 * @throws TskCoreException If the given string is not a valid email address.
	 */
	public static String normalizeEmailAddress(String emailAddress) throws TskCoreException {
		
		EmailValidator validator = EmailValidator.getInstance(true, true);
        if (validator.isValid(emailAddress)) {
            return emailAddress.toLowerCase();
        } else {
            throw new TskCoreException(String.format("Input string is not a valid email address: %s", emailAddress));
        }
	}
	
}
