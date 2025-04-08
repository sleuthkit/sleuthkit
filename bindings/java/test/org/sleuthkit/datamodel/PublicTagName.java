package org.sleuthkit.datamodel;

import org.sleuthkit.datamodel.TagName.HTML_COLOR;

/**
 * Extends TagName with a public constructor for use in test code.
 */
public class PublicTagName extends TagName {

	private static final long serialVersionUID = 1L;
	
	public PublicTagName(long id, String displayName, String description, HTML_COLOR color, TskData.TagType tagType, long tagSetId, int rank) {
		super(id, displayName, description, color, tagType, tagSetId, rank);
	}

	@Override
	public String toString() {
		return "PublicTagName{" + this.getDisplayName() + '}';
	}

}
