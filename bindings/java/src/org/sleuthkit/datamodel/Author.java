/*
 * Sleuth Kit Data Model
 *
 * Copyright 2026 Basis Technology Corp.
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

import org.sleuthkit.datamodel.TskData.TSK_AUTHOR_TYPE_ENUM;

/**
 * A principal that can be attributed as having authored content in a case: a
 * person, a model, or a module. Backed by a row in tsk_authors, obtained
 * through AuthorManager.
 */
public final class Author {

	private final long authorId;
	private final TSK_AUTHOR_TYPE_ENUM type;
	private final String name;
	private final String displayName;

	Author(long authorId, TSK_AUTHOR_TYPE_ENUM type, String name, String displayName) {
		this.authorId = authorId;
		this.type = type;
		this.name = name;
		this.displayName = displayName;
	}

	/**
	 * Gets the id of this author. Internal to the package: a consumer asking
	 * whether two authors are the same principal uses equals() rather than
	 * comparing ids, so that the rule lives in one place.
	 *
	 * @return The author id.
	 */
	long getAuthorId() {
		return authorId;
	}

	/**
	 * Gets the kind of principal this author is.
	 *
	 * @return The author type.
	 */
	public TSK_AUTHOR_TYPE_ENUM getType() {
		return type;
	}

	/**
	 * Gets the stable name of this author: a login name, a model id, or a
	 * module name.
	 *
	 * @return The author name.
	 */
	public String getName() {
		return name;
	}

	/**
	 * Gets the name to render for this author.
	 *
	 * @return The display name.
	 */
	public String getDisplayName() {
		return displayName;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof Author)) {
			return false;
		}
		return authorId == ((Author) obj).authorId;
	}

	@Override
	public int hashCode() {
		return Long.hashCode(authorId);
	}
}
