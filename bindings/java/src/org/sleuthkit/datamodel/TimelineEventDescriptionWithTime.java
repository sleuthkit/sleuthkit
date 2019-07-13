/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 * Bundles a description of an event along with the timestamp for the event. 
 * Used as an intermediate object when parsing data before it is entered into the DB.
 */
final class TimelineEventDescriptionWithTime extends TimelineEventDescription {

   final private long time;

   long getTime() {
	   return time;
   }

   TimelineEventDescriptionWithTime(long time, String shortDescription,
		   String medDescription,
		   String fullDescription) {
	   super(fullDescription, medDescription, shortDescription);
	   this.time = time;
   }
}
