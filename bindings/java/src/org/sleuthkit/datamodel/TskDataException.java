/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011 Basis Technology Corp.
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

/**
 * Data exception that is thrown from Sleuthkit classes.
 */
public class TskDataException extends TskException {

	private static final long serialVersionUID = 123049876L;

	/**
	 * Default constructor when error message is not available
	 */
	public TskDataException() {
		super("No error message available.");
	}

	/**
	 * Create exception containing the error message
	 *
	 * @param msg the message
	 */
	public TskDataException(String msg) {
		super(msg);
	}

	/**
	 * Create exception containing the error message and cause exception
	 *
	 * @param msg the message
	 * @param ex  cause exception
	 */
	public TskDataException(String msg, Exception ex) {
		super(msg, ex);
	}
}
