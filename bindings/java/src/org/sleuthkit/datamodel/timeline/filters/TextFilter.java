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
package org.sleuthkit.datamodel.timeline.filters;

import java.util.Objects;
import javafx.beans.property.Property;
import javafx.beans.property.SimpleStringProperty;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.TimelineManager;

/**
 * Filter for text matching
 */
public class TextFilter implements TimelineFilter {

	private final SimpleStringProperty text = new SimpleStringProperty();

	public TextFilter() {
		this("");
	}

	public TextFilter(String text) {
		this.text.set(text.trim());
	}

	synchronized public void setText(String text) {
		this.text.set(text.trim());
	}

	@Override
	public String getDisplayName() {
		return BundleUtils.getBundle().getString("TextFilter.displayName.text");
	}

	synchronized public String getText() {
		return text.getValue();
	}

	public Property<String> textProperty() {
		return text;
	}

	@Override
	synchronized public TextFilter copyOf() {
		return new TextFilter(getText());
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final TextFilter other = (TextFilter) obj;

		return Objects.equals(text.get(), other.text.get());
	}

	@Override
	public int hashCode() {
		int hash = 5;
		hash = 29 * hash + Objects.hashCode(this.text.get());
		return hash;
	}

	@Override
	public String getSQLWhere(TimelineManager manager) {
		return StringUtils.isNotBlank(this.getText())
				? "((med_description like '%" + this.getText() + "%')" //NON-NLS
				+ " or (full_description like '%" + this.getText() + "%')" //NON-NLS
				+ " or (short_description like '%" + this.getText() + "%'))" //NON-NLS
				: manager.getTrueLiteral();
	}
}
