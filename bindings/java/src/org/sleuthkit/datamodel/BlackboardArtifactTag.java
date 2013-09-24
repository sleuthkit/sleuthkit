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
 * Instances of this class are data transfer objects (DTOs) that represent tags 
 * a user can apply to BlackboardArtifact objects.
 */
public class BlackboardArtifactTag extends Tag {
	private final BlackboardArtifact artifact;
	
	public BlackboardArtifactTag(BlackboardArtifact artifact, TagType type) {
		super(type);
		this.artifact = artifact;
	}
	
	public BlackboardArtifactTag(BlackboardArtifact artifact, TagType type, String comment) {
		super(type, comment);
		this.artifact = artifact;
	}
	
	public BlackboardArtifact getArtifact() {
		return artifact;
	}
}
