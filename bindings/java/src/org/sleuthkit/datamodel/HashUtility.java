/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011-2020 Basis Technology Corp.
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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Map;
import java.util.HashMap;
import java.util.Arrays;

/**
 * Utility to calculate a hash for FsContent and store in TSK database
 */
public class HashUtility {

	private final static int BUFFER_SIZE = 16 * 1024;

	/**
	 * Calculate hashes of the content object.
	 *
	 * @param content   The content object to hash
	 * @param hashTypes The types of hash to compute
	 *
	 * @return A list of the hash results
	 *
	 * @throws TskCoreException
	 */
	static public List<HashResult> calculateHashes(Content content, Collection<HashType> hashTypes) throws TskCoreException {
		Map<HashType, MessageDigest> digests = new HashMap<>();

		for (HashType type : hashTypes) {
			try {
				digests.put(type, MessageDigest.getInstance(type.getName()));
			} catch (NoSuchAlgorithmException ex) {
				throw new TskCoreException("No algorithm found matching name " + type.getName(), ex);
			}
		}

		// Read in byte size chunks and update the hash value with the data.
		byte[] data = new byte[BUFFER_SIZE];
		int totalChunks = (int) Math.ceil((double) content.getSize() / (double) BUFFER_SIZE);
		int read;
		for (int i = 0; i < totalChunks; i++) {
			try {
				read = content.read(data, i * BUFFER_SIZE, BUFFER_SIZE);
			} catch (TskCoreException ex) {
				throw new TskCoreException("Error reading data at address " + i * BUFFER_SIZE + " from content with ID: " + content.getId(), ex);
			}
			
			// Check for EOF
			if (read == -1) {
				break;
			}

			// Only update with the read bytes.
			if (read == BUFFER_SIZE) {
				for (HashType type : hashTypes) {
					digests.get(type).update(data);
				}
			} else {
				byte[] subData = Arrays.copyOfRange(data, 0, read);
				for (HashType type : hashTypes) {
					digests.get(type).update(subData);
				}
			}
		}

		List<HashResult> results = new ArrayList<>();
		for (HashType type : hashTypes) {
			byte hashData[] = digests.get(type).digest();
			StringBuilder sb = new StringBuilder();
			for (byte b : hashData) {
				sb.append(String.format("%02x", b));
			}
			results.add(new HashResult(type, sb.toString()));
		}
		return results;
	}

	/**
	 * Determines whether a string representation of an MD5 hash is valid.
	 *
	 * @param md5Hash The hash.
	 *
	 * @return True or false.
	 */
	public static boolean isValidMd5Hash(String md5Hash) {
		return md5Hash.matches("^[A-Fa-f0-9]{32}$");
	}

	/**
	 * Determines whether a string representation of a SHA-1 hash is valid.
	 *
	 * @param sha1Hash The hash.
	 *
	 * @return True or false.
	 */
	public static boolean isValidSha1Hash(String sha1Hash) {
		return sha1Hash.matches("^[A-Fa-f0-9]{40}$");
	}

	/**
	 * Determines whether a string representation of a SHA-256 hash is valid.
	 *
	 * @param sha256Hash The hash.
	 *
	 * @return True or false.
	 */
	public static boolean isValidSha256Hash(String sha256Hash) {
		return sha256Hash.matches("^[A-Fa-f0-9]{64}$");
	}

	/**
	 * Determine if the passed in Hash value is that for no data (i.e. an empty
	 * file). Looking these values up or correlating on them causes lots of
	 * false positives.
	 *
	 * @param md5
	 *
	 * @return True if it is the empty hash value
	 */
	public static boolean isNoDataMd5(String md5) {
		return md5.toLowerCase().equals("d41d8cd98f00b204e9800998ecf8427e"); //NON-NLS
	}
	
	/**
	 * Utility class to hold a hash value along with its type.
	 */
	public static class HashResult {

		private final HashType type;
		private final String value;

		public HashResult(HashType type, String value) {
			this.type = type;
			this.value = value;
		}

		public HashType getType() {
			return type;
		}

		public String getValue() {
			return value;
		}
	}

	/**
	 * Hash types that can be calculated.
	 */
	public enum HashType {
		MD5("MD5"),
		SHA256("SHA-256");

		private final String name; // This should be the string expected by MessageDigest

		HashType(String name) {
			this.name = name;
		}

		String getName() {
			return name;
		}
	}

	/**
	 * Calculate the MD5 hash for the given FsContent and store it in the
	 * database
	 *
	 * @param file file object whose md5 hash we want to calculate
	 *
	 * @return md5 of the given FsContent object
	 *
	 * @throws java.io.IOException
	 *
	 * @deprecated Use calculateHashes() instead
	 */
	@Deprecated
	static public String calculateMd5(AbstractFile file) throws IOException {
		Logger logger = Logger.getLogger(HashUtility.class.getName());
		String md5Hash = calculateMd5Hash(file);
		try {
			file.getSleuthkitCase().setMd5Hash(file, md5Hash);
		} catch (TskCoreException ex) {
			logger.log(Level.WARNING, "Error updating content's md5 in database", ex); //NON-NLS
		}
		return md5Hash;
	}
	
	/**
	 * Calculate the MD5 hash for the given FsContent
	 *
	 * @param content content object whose md5 hash we want to calculate
	 *
	 * @return md5 of the given FsContent object
	 *
	 * @throws java.io.IOException
	 * 
	 * @decprecated Use calculateHashes() instead
	 */
	@Deprecated
	static public String calculateMd5Hash(Content content) throws IOException {
		try {
			List<HashResult> results = calculateHashes(content, Arrays.asList(HashType.MD5));
			return results.stream()
				.filter(result -> result.getType().equals(HashType.MD5))
				.findFirst().get().getValue();
			
		} catch (TskCoreException ex) {
			// Wrap in an IOException to retain the current method signature
			throw new IOException(ex);
		}
	}	
}