/*
 * SleuthKit Java Bindings
 *
 * Copyright 2020 Basis Technology Corp.
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
package org.sleuthkit.datamodel.filerepository;

/**
 * Utility class to hold the file repository server settings.
 */
public class FileRepositorySettings {

	private final String address;
	private final String port;
	
	/**
	 * Create a FileRepositorySettings instance for the server.
	 *
	 * @param address The IP address/hostname of the server.
	 * @param port    The port.
	 */
	public FileRepositorySettings(String address, String port) {
		this.address = address;
		this.port = port;
	}
	
	/**
	 * Fills in an API template with the address and port.
	 */
	String createBaseURL(String urlTemplate) {
		return String.format(urlTemplate, address, port);
	}
}
