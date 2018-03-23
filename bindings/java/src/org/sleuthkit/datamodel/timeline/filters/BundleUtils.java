package org.sleuthkit.datamodel.timeline.filters;


import org.sleuthkit.datamodel.timeline.*;
import java.util.ResourceBundle;


class BundleUtils {

	private static final ResourceBundle BUNDLE = ResourceBundle.getBundle("org.sleuthkit.datamodel.timeline.filters.Bundle");

	static ResourceBundle getBundle() {
		return BUNDLE;
	}
}
