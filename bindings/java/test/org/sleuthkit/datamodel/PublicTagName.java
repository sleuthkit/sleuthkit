package org.sleuthkit.datamodel;

import org.sleuthkit.datamodel.TagName.HTML_COLOR;

/**
 * Extands TagName with a public constructor for use in test code.
 */
public class PublicTagName extends TagName {

	public PublicTagName(long id, String displayName, String description, HTML_COLOR color, TskData.FileKnown knownStatus) {
		super(id, displayName, description, color, knownStatus);
	}

	@Override
	public String toString() {
		return "PublicTagName{" + this.getDisplayName() + '}';
	}

}
