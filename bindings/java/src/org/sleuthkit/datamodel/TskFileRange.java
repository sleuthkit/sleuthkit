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

/**
 * An object representation of an entry in tsk_file_layout table
 * Any file can have one or more file ranges defined to specify physical file layout.
 * This is especially useful for non-fs "virtual" files created for the purpose of data analysis
 */
public class TskFileRange {
	private long obj_id;
	private long byteStart;
	private long byteLen;
	private long sequence;
	
	/**
	 * Create file range to map the database object
	 * @param obj_id object id of the associated file
	 * @param byteStart byte start with respect to the image
	 * @param byteLen length of the range in bytes
	 * @param sequence sequence order of the range for the file
	 */
	public TskFileRange(long obj_id, long byteStart, long byteLen, long sequence) {
		this.obj_id = obj_id;
		this.byteStart = byteStart;
		this.byteLen = byteLen;
		this.sequence = sequence;
	}
	
	/**
	 * Get object id of the file associated
	 * @return object id of the associated file
	 */
	public long getID() {
		return obj_id;
	}
	
	/**
	 * Get start byte of the range, with respect to the image
	 * @return start bye of the range
	 */
	public long getByteStart() {
		return byteStart;
	}
	
	/**
	 * Get the byte length of the range
	 * @return length in bytes
	 */
	public long getByteLen() {
		return byteLen;
	}
	
	/**
	 * Get sequence of this range defining ordering of this range with respect 
	 * to other ranges for the file
	 * @return sequence number of this range
	 */
	public long getSequence() {
		return sequence;
	}
}
