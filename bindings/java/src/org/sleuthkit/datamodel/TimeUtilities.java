/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2017 Basis Technology Corp.
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

import java.text.SimpleDateFormat;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Time related utility methods
 *
 */
public class TimeUtilities {
	private static final Logger LOGGER = Logger.getLogger(TimeUtilities.class.getName());
	private static final SimpleDateFormat DATE_FORMATTER = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
	
	/**
	 * Return the epoch into string in ISO 8601 dateTime format
	 *
	 * @param epoch time in seconds
	 *
	 * @return formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 */
	public static String epochToTime(long epoch) {
		String time = "0000-00-00 00:00:00";
		if (epoch != 0) {
			time = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss z").format(new java.util.Date(epoch * 1000));
		}
		return time;
	}

	/**
	 * Return the epoch into string in ISO 8601 dateTime format, 
	 * in the given timezone
	 *
	 * @param epoch time in seconds
	 * @param tzone time zone
	 *
	 * @return formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 */
	public static String epochToTime(long epoch, TimeZone tzone) {
		String time = "0000-00-00 00:00:00";
		if (epoch != 0) {
			synchronized (DATE_FORMATTER) {
				DATE_FORMATTER.setTimeZone(tzone);
				time = DATE_FORMATTER.format(new java.util.Date(epoch * 1000));
			}
		}
		return time;
	}
	
	/**
	 * Convert from ISO 8601 formatted date time string to epoch time in seconds
	 *
	 * @param time formatted date time string as "yyyy-MM-dd HH:mm:ss"
	 *
	 * @return epoch time in seconds
	 */
	public static long timeToEpoch(String time) {
		long epoch = 0;
		try {
			epoch = new java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse(time).getTime() / 1000;
		} catch (Exception e) {
			LOGGER.log(Level.WARNING, "Failed to parse time string", e); //NON-NLS
		}

		return epoch;
	}
}
