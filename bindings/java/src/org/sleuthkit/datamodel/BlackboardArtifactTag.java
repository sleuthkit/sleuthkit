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
 * a user can apply to blackboard artifacts.
 */
public class BlackboardArtifactTag extends Tag {

	private final BlackboardArtifact artifact;
	private final Content content;

	// Clients of the org.sleuthkit.datamodel package should not directly create these objects.	
	BlackboardArtifactTag(long id, BlackboardArtifact artifact, Content content, TagName name, String comment) {
		super(id, name, comment);
		this.artifact = artifact;
		this.content = content;
	}

	public BlackboardArtifact getArtifact() {
		return artifact;
	}

	public Content getContent() {
		return content;
	}
}
