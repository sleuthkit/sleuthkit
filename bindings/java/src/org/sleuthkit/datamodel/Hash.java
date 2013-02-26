/*
 * Autopsy Forensic Browser
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

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.io.InputStream;

/**
 * Utility to calculate a hash for FsContent and store in tsk database
 */
public class Hash {

	private final static int BUFFER_SIZE = 16 * 1024;
	private final byte[] buffer = new byte[BUFFER_SIZE];

	/**
	 * Generate the md5 hash for the given FsContent and store it in the
	 * database
	 *
	 * @param file file object whose md5 hash we want to calculate
	 * @return md5 of the given FsContent object
	 */
	public String calculateMd5(AbstractFile file) throws IOException {
		String hashText = "";
		InputStream in = new ReadContentInputStream(file);
		Logger logger = Logger.getLogger(Hash.class.getName());
		try {
			MessageDigest md = MessageDigest.getInstance("md5");
			int len = in.read(buffer);
			while (len != -1) {
				md.update(buffer, 0, len);
				len = in.read(buffer);
			}
			byte[] hash = md.digest();
			BigInteger bigInt = new BigInteger(1, hash);
			hashText = bigInt.toString(16);
			// zero padding
			while (hashText.length() < 32) {
				hashText = "0" + hashText;
			}
			file.getSleuthkitCase().setMd5Hash(file, hashText);
		} catch (NoSuchAlgorithmException ex) {
			logger.log(Level.WARNING, "No algorithm known as 'md5'", ex);
		} catch (TskCoreException ex) {
			logger.log(Level.WARNING, "Error updating content's md5 in database", ex);
		} finally {
			in.close();
		}
		return hashText;
	}
}
