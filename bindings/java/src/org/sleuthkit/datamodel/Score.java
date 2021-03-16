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
 * Encapsulates either an analysis result score or the aggregate score of Content. 
 * A score measures how likely the Content object is to be relevant to an investigation.
 * Relevance is determined by a series of analysis techniques, each of which has a score. 
 * The aggregate score for an item is then determined based on its analysis results.
 *
 * A score has two primary fields: Significance and Confidence, though it should be 
 * noted that the significance has a concept of confidence in it as well. So, it can get
 * a bit confusing. 
 *
 * There are two confidence levels: Normal and User Defined. Normal confidence results come
 * from various (automated) analysis modules.  "User Defined" comes from a user manually assigning
 * a score to the item.  The "User Defined" scores will overrule the automated scores. 
 * Modules should be making Normal confidence scores. 
 *
 * The significance is a range of how Notable (i.e. "Bad") the item is. The range is from
 * NONE (i.e. "Good") to NOTABLE with values in the middle, such as LIKELY_NOTABLE for 
 * suspicious items.  The LIKELY_ values are used when there is less confidence in the result. 
 * The significance has to do with the false positive rate at actually detecting notable or
 * benign things. 
 *
 * For an example, if a file is found in a MD5 hashset of notable files, then a module would 
 * use a significance of NOTABLE with NORMAL confidence.  This is because the MD5 is exact
 * match and the hash set is all notable files. 
 *
 * For a keyword hit, the significance would be LIKELY_NOTABLE because keywords often can be 
 * used in both good and bad ways. A user will need to review the file to determine if it is
 * a true or false positive. 
 * 
 * If a file is found to be on a good list (via MD5), then it could have a significance of NONE
 * and then other modules could ignore it. 
 *
 * An aggregate score is the combination of the specific analysis results. USER_RESULTS will 
 * overrule NORMAL.  NOTABLE overrules NONE. Both of those overrule the LIKELY_* results. 
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

		UNKNOWN(0, bundle.getString("Significance.Unknown.text")),				// no analysis has been performed to ascertain significance.
		LIKELY_NONE(8, bundle.getString("Significance.LikelyNone.text")),		// likely good
		LIKELY_NOTABLE(9, bundle.getString("Significance.LikelyNotable.text")),	// likely bad, suspicious
		NONE(18, bundle.getString("Significance.None.text")),					// good
		NOTABLE(19, bundle.getString("Significance.Notable.text"));				// bad
		
		private final int id;
		private final String name;

		private Significance(int id, String name) {
			this.id = id;
			this.name = name;
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

		public int getId() {
			return id;
		}

		public String getName() {
			return name;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	/**
	 * Encapsulates confidence in the assigned significance.
	 *
	 * This is a broad measure of confidence - significance assigned by a user
	 * overrules the significance assigned by automated analysis.
	 *
	 */
	public enum Confidence {

		NONE(0, bundle.getString("Confidence.None.text")), // < Used with "Unknown" significance
		NORMAL(30, bundle.getString("Confidence.Normal.text")), // < automatic analysis results have normal conidence.
		USER_DEFINED(50, bundle.getString("Confidence.UserDefined.text")); //< Reservied for examiner-tagged results. Human judgement overrules module results. 

		private final int id;
		private final String name;

		private Confidence(int id, String name) {
			this.id = id;
			this.name = name;
		}

		public static Confidence fromString(String name) {
			return Arrays.stream(values())
					.filter(val -> val.getName().equals(name))
					.findFirst().orElse(NONE);
		}

		static public Confidence fromID(int id) {
			return Arrays.stream(values())
					.filter(val -> val.getId() == id)
					.findFirst().orElse(NONE);
		}

		public int getId() {
			return id;
		}

		public String getName() {
			return name;
		}

		@Override
		public String toString() {
			return name;
		}
	}

	public static final Score SCORE_UNKNOWN = new Score(Significance.UNKNOWN, Confidence.NONE);
	
	// Score is a combination of significance and confidence.
	private final Significance significance;
	private final Confidence confidence;

	public Score(Significance significance, Confidence confidence) {
		this.significance = significance;
		this.confidence = confidence;
	}

	public Significance getSignificance() {
		return significance;
	}

	public Confidence getConfidence() {
		return confidence;
	}

	@Override
	public int compareTo(Score other) {
		// A score is a combination of significance & confidence
		// Higher confidence wins.  
		// If two results have same confidence, then the higher significance wins
		if (this.getConfidence() != other.getConfidence()) {
			return this.getConfidence().ordinal() - other.getConfidence().ordinal();
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
