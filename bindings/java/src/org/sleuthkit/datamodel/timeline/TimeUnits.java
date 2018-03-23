/*
 * Sleuth Kit Data Model
 *
 * Copyright 2018 Basis Technology Corp.
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
package org.sleuthkit.datamodel.timeline;

import java.time.temporal.ChronoUnit;
import org.joda.time.Days;
import org.joda.time.Hours;
import org.joda.time.Minutes;
import org.joda.time.Months;
import org.joda.time.Period;
import org.joda.time.Seconds;
import org.joda.time.Years;

/**
 * predefined units of time for use in choosing axis labels and sub intervals.
 */
public enum TimeUnits implements DisplayNameProvider {

	FOREVER(null, ChronoUnit.FOREVER),
	YEARS(Years.ONE.toPeriod(), ChronoUnit.YEARS),
	MONTHS(Months.ONE.toPeriod(), ChronoUnit.MONTHS),
	DAYS(Days.ONE.toPeriod(), ChronoUnit.DAYS),
	HOURS(Hours.ONE.toPeriod(), ChronoUnit.HOURS),
	MINUTES(Minutes.ONE.toPeriod(), ChronoUnit.MINUTES),
	SECONDS(Seconds.ONE.toPeriod(), ChronoUnit.SECONDS);

	private final Period period;

	private final ChronoUnit chronoUnit;

	public static TimeUnits fromChronoUnit(ChronoUnit chronoUnit) {
		switch (chronoUnit) {

			case FOREVER:
				return FOREVER;
			case ERAS:
			case MILLENNIA:
			case CENTURIES:
			case DECADES:
			case YEARS:
				return YEARS;
			case MONTHS:
				return MONTHS;
			case WEEKS:
			case DAYS:
				return DAYS;
			case HOURS:
			case HALF_DAYS:
				return HOURS;
			case MINUTES:
				return MINUTES;
			case SECONDS:
			case MILLIS:
			case MICROS:
			case NANOS:
				return SECONDS;
			default:
				return YEARS;
		}
	}

	public Period getPeriod() {
		return period;
	}

	public ChronoUnit getChronoUnit() {
		return chronoUnit;
	}

	private TimeUnits(Period period, ChronoUnit chronoUnit) {
		this.period = period;
		this.chronoUnit = chronoUnit;
	}

	@Override
	public String getDisplayName() {
		return toString();
	}
}
