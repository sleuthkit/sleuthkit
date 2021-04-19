/*
 * Sleuth Kit Data Model
 *
 * Copyright 2021 Basis Technology Corp.
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
 * This content type is used as a default when the object type from the
 * tsk_objects table is not present in the TskData.ObjectType enum. This should
 * only come into play when loading case databases created by a newer version of
 * Autopsy.
 */
public class UnsupportedContent extends AbstractContent {

	/**
	 * Create an UnsupportedContent object. Only store the object id.
	 *
	 * @param db     case database handle
	 * @param obj_id object id
	 */
	protected UnsupportedContent(SleuthkitCase db, long obj_id) {
		super(db, obj_id, "Unsupported Content");
	}

	@Override
	public int read(byte[] buf, long offset, long len) throws TskCoreException {
		return 0;
	}

	@Override
	public void close() {
		// Do nothing
	}

	@Override
	public long getSize() {
		return 0;
	}

	@Override
	public <T> T accept(ContentVisitor<T> v) {
		return v.visit(this);
	}

	@Override
	public <T> T accept(SleuthkitItemVisitor<T> v) {
		return v.visit(this);
	}
}
