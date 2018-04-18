package org.sleuthkit.datamodel.timeline.filters;

import java.util.ResourceBundle;

final class BundleUtils {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.filters.Bundle");

	static ResourceBundle getBundle() {
		return BUNDLE;
	}

	private BundleUtils() {
	}
}
