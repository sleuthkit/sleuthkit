/*
 * Sleuth Kit Data Model
 *
 * Copyright 2020 Basis Technology Corp.
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

/**
 * Encapsulates either an analysis result score or the final score of Content. 
 * A score measures how likely the Content object is to be relevant to an investigation.
 * Relevance is determined by a series of analysis techniques, each of which has a score. 
 * The final score for an item is then determined based on its analysis results.
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
 * significance will be HIGH because the car's existence is surely notable. But, if
 * there are some good and some bad, then it should have a significance of MEDIUM (or LOW).
 * Any module that detects green convertibles should have the same significance. 
 * But, different modules may have different confidences based on their approach. 
 * If a module can accurately detect a green convertible, then it should have HIGH
 * confidence. But, if a module can't differentiate a convertible from a truck or
 * green from yellow, then it should have MEDIUM confience (or lower). 
 * 
 * For a more traditional example, if a file is found in a MD5 hashset of notable files, 
 * then it would get HIGH significance because the hashset contains only known notable
 * files. And it would get HIGH confidence because the MD5 calculation and lookup 
 * process are exact matches and there is no guessing.
 *
 * For a keyword hit, the significance could be MEDIUM if the word exists in both
 * good and bad contexts, but the confidence would be HIGH because we know the word 
 * existed in a document. 
 * 
 * If a file is found to be on a good list, then it could have a significance of NONE
 * and then other modules could ignore it. 
 * The confidence could be HIGH if it was based on an exact match MD5 or MEDIUM if it 
 * was based on only file name and size and we aren't entirely sure what the content was.
 */
public class Score implements Comparable<Score> {

	/**
	 * Indicates the relevance of an item based on the analysis result's conclusion.
     * Significance is tied to an analysis technique type. 
	 */
	public enum Significance {

		NONE(0, "None"),		//< Item is Good and has no (bad) significance
		UNKNOWN(10, "Unknown"), //< no analysis has been performed to ascertain significance.
		LOW(20, "Low"),
		MEDIUM(30, "Medium"), //< Suspicious.  Could be good or bad. 
		HIGH(40, "High");	//< Bad & notable

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
	 * Encapsulates confidence in the analysis technique's implementation on the conclusion.
	 * Higher confidence implies fewer false positives. For example, an object detection
     * result may have lower confidence than one based looking for a specific byte sequence. 
	 */
	public enum Confidence {

		NONE(0, "None"), //< Used with "Unknown" significance
		LOWEST(10, "Lowest"), //< Very high false positive rates
		LOW(20, "Low"),
		MEDIUM(30, "Medium"), //< Some false positives
		HIGH(40, "High"),   //< No false positives
		HIGHEST(50, "Highest"); //< Reservied for examiner-tagged results. Human judgement overrules module results. 

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
