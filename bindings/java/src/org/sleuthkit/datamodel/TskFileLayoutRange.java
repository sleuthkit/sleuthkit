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
 *
 * @author dfickling
 */
public class TskFileLayoutRange {
	private long obj_id;
	private long byteStart;
	private long byteLen;
	private long sequence;
	
	public TskFileLayoutRange(long obj_id, long byteStart, long byteLen, long sequence) {
		this.obj_id = obj_id;
		this.byteStart = byteStart;
		this.byteLen = byteLen;
		this.sequence = sequence;
	}
	
	public long getID() {
		return obj_id;
	}
	
	public long getByteStart() {
		return byteStart;
	}
	
	public long getByteLen() {
		return byteLen;
	}
	
	public long getSequence() {
		return sequence;
	}
}
