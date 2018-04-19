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
 * A singleton EventType to represent the root type of all event types.
 */
public final class RootEventType extends AbstractEventType {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.eventtype.Bundle");  // NON-NLS

	@Override
	@SuppressWarnings("deprecation")
	public ImmutableSortedSet<? extends EventType> getSiblingTypes() {
		return ImmutableSortedSet.of(this);
	}

	@Override
	public EventTypeZoomLevel getZoomLevel() {
		return EventTypeZoomLevel.ROOT_TYPE;
	}

	private RootEventType() {
		super(0, BUNDLE.getString("RootEventType.eventTypes.name"), EventTypeZoomLevel.ROOT_TYPE, null, BaseType.values());
	}

	public static RootEventType getInstance() {
		return RootEventTypeHolder.INSTANCE;
	}

	@Override
	public int getTypeID() {
		return 0;
	}

	private static class RootEventTypeHolder {

		private static final RootEventType INSTANCE = new RootEventType();

		private RootEventTypeHolder() {
		}
	}

	@Override
	public RootEventType getSuperType() {
		return this;
	}
}
