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
 * A score has two primary fields: Significance and Confidence. Significance is based on 
 * what the analysis technique is measuring and if its goal is to detect good, bad, or 
 * suspicious. The significance is more about the technique and less about a specific
 * implementation of the technique. 
 * Confidence reflects how confident the analysis technique implementation was in its conclusion
 * and is based on the false positive rate of that implementation. 
 *
 * Let's first look at a made up example. Lets say that in some crazy world, we
 * can detect if a car is "bad" based on its color and we have a module to look for
 * green convertibles. This module's significance is based on how many green 
 * convertibles are bad overall. If all green convertibles are bad, then its 
 * significance will be NOTABLE because the car's existence is surely notable. But, if
 * there are some good and some bad, then it should have a significance of LIKELY_NOTABLE (or LOW).
 * Any module that detects green convertibles should have the same significance. 
 * But, different modules may have different confidences based on their approach. 
 * If a module can accurately detect a green convertible, then it should have NOTABLE
 * confidence. But, if a module can't differentiate a convertible from a truck or
 * green from yellow, then it should have LIKELY_NOTABLE confidence (or lower). 
 * 
 * For a more traditional example, if a file is found in a MD5 hashset of notable files, 
 * then it would get NOTABLE significance because the hashset contains only known notable
 * files. And it would get NOTABLE confidence because the MD5 calculation and lookup 
 * process are exact matches and there is no guessing.
 *
 * For a keyword hit, the significance could be LIKELY_NOTABLE if the word exists in both
 * good and bad contexts, but the confidence would be NOTABLE because we know the word 
 * existed in a document. 
 * 
 * If a file is found to be on a good list, then it could have a significance of NONE
 * and then other modules could ignore it. 
 * 
 */
public class Score implements Comparable<Score> {

	private static final ResourceBundle bundle = ResourceBundle.getBundle("org.sleuthkit.datamodel.Bundle");
	/**
	 * Indicates the relevance of an item based on the analysis result's conclusion.
     * Significance is tied to an analysis technique type. 
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
	 * trumps the significance assigned by automated analysis.
	 *
	 */
	public enum Confidence {

		NORMAL(0, bundle.getString("Confidence.Normal.text")), // < automatic analysis results have normal conidence.
		USER_DEFINED(10, bundle.getString("Confidence.UserDefined.text")); //< Reservied for examiner-tagged results. Human judgement overrules module results. 

		private final int id;
		private final String name;

		private Confidence(int id, String name) {
			this.id = id;
			this.name = name;
		}

		public static Confidence fromString(String name) {
			return Arrays.stream(values())
					.filter(val -> val.getName().equals(name))
					.findFirst().orElse(NORMAL);
		}

		static public Confidence fromID(int id) {
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

		@Override
		public String toString() {
			return name;
		}
	}

	public static final Score SCORE_UNKNOWN = new Score(Significance.UNKNOWN, Confidence.NORMAL);
	
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
