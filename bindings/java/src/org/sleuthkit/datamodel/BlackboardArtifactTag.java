/*
 * Sleuth Kit Data Model
 * 
 * Copyright 2013 Basis Technology Corp.
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

/**
 * Instances of this class represent tags a user applies to an artifact of a 
 * file or a portion of a file.
 */
public class BlackboardArtifactTag extends AbstractFileTag {
	private final BlackboardArtifact artifact;
	
	public BlackboardArtifactTag(AbstractFile file, BlackboardArtifact artifact, TagName name) {
		super(file, name);
		this.artifact = artifact;
	}
	
	public BlackboardArtifactTag(AbstractFile file, BlackboardArtifact artifact, TagName name, String comment) {
		super(file, name, comment);
		this.artifact = artifact;
	}
	
	public BlackboardArtifactTag(AbstractFile file, BlackboardArtifact artifact, TagName name, String comment, long beginByteOffset, long endByteOffset) {
		super(file, name, comment, beginByteOffset, endByteOffset);
		this.artifact = artifact;
	}
	
	public BlackboardArtifact getArtifact() {
		return artifact;
	}

	// This method is package-private because its only intended client is the
	// SleuthkitCase (i.e., database access) class. 
	BlackboardArtifactTag(long id, AbstractFile file, BlackboardArtifact artifact, TagName name, String comment, long beginByteOffset, long endByteOffset) {
		super(id, file, name, comment, beginByteOffset, endByteOffset);
		this.artifact = artifact;
	}	
}
