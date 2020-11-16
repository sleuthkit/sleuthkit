package org.sleuthkit.datamodel;

import org.sleuthkit.datamodel.TagName.HTML_COLOR;

/**
 * Extands TagName with a public constructor for use in test code.
 */
public class PublicTagName extends TagName {

	public PublicTagName(long id, String displayName, String description, HTML_COLOR color, TskData.FileKnown knownStatus, long tagSetId, int rank) {
		super(id, displayName, description, color, knownStatus, tagSetId, rank);
	}

	@Override
	public String toString() {
		return "PublicTagName{" + this.getDisplayName() + '}';
	}

}
