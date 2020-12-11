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
 *
 * Encapsulates a final score of an artifact. Computed by taking into account
 * all of the analysis results.
 */
public class Score implements Comparable<Score> {

	/**
	 * Enum to encapsulate significance of a analysis result.
	 *
	 */
	public enum Significance {

		NONE(0, "None"),		// has no (bad) significance, i.e. it's Good
		UNKNOWN(10, "Unknown"), // no analysis has been performed to ascertain significance.
		LOW(20, "Low"),
		MEDIUM(30, "Medium"), // Suspicious
		HIGH(40, "High");	// Bad & Notable

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
	 * Encapsulates confidence in a analysis result.
	 *
	 * Higher confidence implies fewer false positives.
	 */
	public enum Confidence {

		NONE(0, "None"),
		LOWEST(10, "Lowest"),
		LOW(20, "Low"),
		MEDIUM(30, "Medium"),
		HIGH(40, "High"),
		HIGHEST(50, "Highest");

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
