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
package org.sleuthkit.datamodel.timeline;

import java.util.Arrays;
import java.util.List;
import javafx.scene.image.Image;
import static org.sleuthkit.datamodel.timeline.BundleUtils.getBundle;

/**
 * RootTypes are event types that have no super type.
 */
public enum BaseTypes implements EventType {
	FILE_SYSTEM(1,getBundle().getString("BaseTypes.fileSystem.name"), "blue-document.png") { // NON-NLS

		@Override
		public List<? extends EventType> getSubTypes() {
			return Arrays.asList(FileSystemTypes.values());
		}

		@Override
		public EventType getSubType(String string) {
			return FileSystemTypes.valueOf(string);
		}
	},
	WEB_ACTIVITY(2,getBundle().getString("BaseTypes.webActivity.name"), "web-file.png") { // NON-NLS

		@Override
		public List<? extends EventType> getSubTypes() {
			return Arrays.asList(WebTypes.values());
		}

		@Override
		public EventType getSubType(String string) {
			return WebTypes.valueOf(string);
		}
	},
	MISC_TYPES(3,getBundle().getString("BaseTypes.miscTypes.name"), "block.png") { // NON-NLS

		@Override
		public List<? extends EventType> getSubTypes() {
			return Arrays.asList(MiscTypes.values());
		}

		@Override
		public EventType getSubType(String string) {
			return MiscTypes.valueOf(string);
		}
	};
	private final int id;

	public int getTypeID() {
		return id;
	}

	private final String displayName;

	private final String iconBase;

	private final Image image;

	@Override
	public Image getFXImage() {
		return image;
	}

	@Override
	public String getIconBase() {
		return iconBase;
	}

	@Override
	public EventTypeZoomLevel getZoomLevel() {
		return EventTypeZoomLevel.BASE_TYPE;
	}

	@Override
	public String getDisplayName() {
		return displayName;
	}

	private BaseTypes(int id, String displayName, String iconBase) {
		this.id = id;
		this.displayName = displayName;
		this.iconBase = iconBase;
		this.image = new Image("org/sleuthkit/autopsy/timeline/images/" + iconBase, true); // NON-NLS
	}

	@Override
	public EventType getSuperType() {
		return RootEventType.getInstance();
	}

	@Override
	public EventType getSubType(String string) {
		return BaseTypes.valueOf(string);
	}
}
