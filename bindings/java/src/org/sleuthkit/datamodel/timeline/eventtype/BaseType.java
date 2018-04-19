/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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
package org.sleuthkit.datamodel.timeline.eventtype;

import com.google.common.collect.ImmutableSortedSet;
import java.util.ResourceBundle;
import org.sleuthkit.datamodel.timeline.EventTypeZoomLevel;

/**
 * RootTypes are event types that have no super type.
 */
public final class BaseType extends AbstractEventType {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.eventtype.Bundle");

	public static final BaseType FILE_SYSTEM = new BaseType(1, BUNDLE.getString("BaseTypes.fileSystem.name"),
			FileSystemType.values());
	public static final BaseType WEB_ACTIVITY = new BaseType(2, BUNDLE.getString("BaseTypes.webActivity.name"),
			WebType.values());
	public static final BaseType MISC_TYPES = new BaseType(3, BUNDLE.getString("BaseTypes.miscTypes.name"),
			MiscType.values());

	@SuppressWarnings("deprecation")
	private static final ImmutableSortedSet<BaseType> VALUES
			= ImmutableSortedSet.of(FILE_SYSTEM, WEB_ACTIVITY, MISC_TYPES);

	static ImmutableSortedSet< BaseType> values() {
		return VALUES;
	}

	private BaseType(int id, String displayName, ImmutableSortedSet<? extends EventType> subTypes) {
		super(id, displayName, EventTypeZoomLevel.BASE_TYPE, RootEventType.getInstance(), subTypes);
	}

}
