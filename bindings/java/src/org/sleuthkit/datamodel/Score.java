/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020-2021 Basis Technology Corp.
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

import java.util.Arrays;
import java.util.Comparator;
import java.util.ResourceBundle;

/**
 * Encapsulates either an analysis result score or the aggregate score of
 * Content. A score measures how likely the Content object is to be relevant to
 * an investigation. Relevance is determined by a series of analysis techniques,
 * each of which has a score. The aggregate score for an item is then determined
 * based on its analysis results.
 *
 * A score has two primary fields: Significance and Priority.
 *
 * There are two priorities : Normal and Override. Nearly everything should have
 * a "Normal" priority. "Override" is used when a user wants to change the score
 * because of a false positive.  An "Override" score will take priority over 
 * the combined "Normal" scores.  An item should have only one "Override" score
 * at a time, but that is not currently enforced. 
 *
 * The significance is a range of how Notable (i.e. "Bad") the item is. The
 * range is from NONE (i.e. "Good") to NOTABLE with values in the middle, such
 * as LIKELY_NOTABLE for suspicious items. The LIKELY_ values are used when
 * there is less confidence in the result. The significance has to do with the
 * false positive rate at actually detecting notable or benign things.
 *
 *
 * For an example, if a file is found in a MD5 hashset of notable files, then a
 * module would use a significance of NOTABLE. This is because the MD5 is exact
 * match and the hash set is all notable files.
 *
 * For a keyword hit, the significance would be LIKELY_NOTABLE because keywords
 * often can be used in both good and bad ways. A user will need to review the
 * file to determine if it is a true or false positive.
 *
 * If a file is found to be on a good list (via MD5), then it could have a
 * significance of NONE and then other modules could ignore it.
 *
 * An aggregate score is the combination of the specific analysis results.
 * USER_RESULTS will overrule NORMAL. NOTABLE overrules NONE. Both of those
 * overrule the LIKELY_* results. 
 * 
 * NOTABLE > NONE > LIKELY_NOTABLE > LIKELY_NONE > UNKNOWN
 */
public class Score implements Comparable<Score> {

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	/**
	 * Indicates the relevance of an item based on the analysis result's conclusion.
         * 
	 * For comparing significance, the following ordering applies
	 * 
	 * Bad > Good > Likely Bad > Likely Good > Unknown
	 * 
	 */
	public enum Significance {

		// Enum name must not have any spaces.

        /* Notes on the ordinal numbers: We defined these so that we could easily
         * compare values while also have some concept of grouping. 
         * The 1x values are a higher confidence than the 0x files.
         * NOTABLE (x9) has priority over NOT NOTABLE (x8). 
         * If we need to make this more complicated in the future, we can add
         * other groupings, such as 14 and 15. 
         */
		
		/// no significance assigned yet.
		UNKNOWN(0, "Unknown", "Significance.Unknown.displayName.text"),	
		
		/// likely good		
		LIKELY_NONE(8, "LikelyNone", "Significance.LikelyNone.displayName.text"),
		
		/// likely bad, suspicious
		LIKELY_NOTABLE(9, "LikelyNotable", "Significance.LikelyNotable.displayName.text"),	
		
		/// good
		NONE(18, "None", "Significance.None.displayName.text"),		
		
		/// bad
		NOTABLE(19, "Notable", "Significance.Notable.displayName.text");				
		
		private final int id;
		private final String name;	// name must not have spaces
		private final String displayNameKey; // display name is loaded from resource bundle using this key.

		private Significance(int id, String name, String displayNameKey) {
			this.id = id;
			this.name = name;
			this.displayNameKey = displayNameKey;
		}

		public static Significance fromString(String name) {
			return Arrays.stream(values())
					.filter(val -> val.getName().equals(name))
					.findFirst().orElse(NONE);
		}

		static public Significance fromID(int id) {
			return Arrays.stream(values())
					.filter(val -> val.getId() == id)
					.findFirst().orElse(NONE);
		}

		/**
		 * Get enum ordinal.
		 * 
		 * @return Ordinal.
		 */
		public int getId() {
			return id;
		}

        /**
         * Gets name that has no spaces in it.
         * Does not get translated.
		 * 
		 * @return Name.
         */
		public String getName() {
			return name;
		}

        /**
         * Gets display name that may have spaces and can be used in the UI.
         * May return a translated version. 
		 * 
		 * @return Display name.
         */
		public String getDisplayName() {
			return  bundle.getString(displayNameKey);
		}
			
		@Override
		public String toString() {
			return name;
		}
	}

	/**
	 * Represents the priority of the score to allow overrides by a user or module
	 */
	public enum Priority {

		// Name must not have any spaces.
		NORMAL(0, "Normal",  "Score.Priority.Normal.displayName.text"),
		OVERRIDE(10, "Override", "Score.Priority.Override.displayName.text"); 

		private final int id;
		private final String name; 
		private final String displayNameKey; // display name is loaded from resource bundle using this key.
		
		private Priority(int id, String name, String displayNameKey) {
			this.id = id;
			this.name = name;
			this.displayNameKey = displayNameKey;
		}

		public static Priority fromString(String name) {
			return Arrays.stream(values())
					.filter(val -> val.getName().equals(name))
					.findFirst().orElse(NORMAL);
		}

		static public Priority fromID(int id) {
			return Arrays.stream(values())
					.filter(val -> val.getId() == id)
					.findFirst().orElse(NORMAL);
		}

		public int getId() {
			return id;
		}

		public String getName() {
			return name;
		}

		public String getDisplayName() {
			return bundle.getString(displayNameKey);
		}
		
		@Override
		public String toString() {
			return name;
		}
	}

	public static final Score SCORE_NOTABLE = new Score(Significance.NOTABLE, Priority.NORMAL);
	public static final Score SCORE_LIKELY_NOTABLE = new Score(Significance.LIKELY_NOTABLE, Priority.NORMAL);	
	public static final Score SCORE_LIKELY_NONE = new Score(Significance.LIKELY_NONE, Priority.NORMAL);
	public static final Score SCORE_NONE= new Score(Significance.NONE, Priority.NORMAL);
	
	public static final Score SCORE_UNKNOWN = new Score(Significance.UNKNOWN, Priority.NORMAL);
	
	// Score is a combination of significance and priority.
	private final Significance significance;
	private final Priority priority;

	public Score(Significance significance, Priority priority) {
		this.significance = significance;
		this.priority = priority;
	}

	public Significance getSignificance() {
		return significance;
	}

	public Priority getPriority() {
		return priority;
	}

	@Override
	public int compareTo(Score other) {
		// A score is a combination of significance & priority.
		// Priority Override overrides Normal.
		// If two results have same priority, then the higher significance wins.
		if (this.getPriority() != other.getPriority()) {
			return this.getPriority().ordinal() - other.getPriority().ordinal();
		} else {
			return this.getSignificance().ordinal() - other.getSignificance().ordinal();
		}
	}
	
	 public static final Comparator<Score> getScoreComparator() {
        return (Score score1, Score score2) -> {
			return score1.compareTo(score2);
        };
    }
}
