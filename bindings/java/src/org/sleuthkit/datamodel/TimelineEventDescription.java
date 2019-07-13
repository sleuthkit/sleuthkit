/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 * Encapsulates the potential multiple levels of description for an event in
 * to one object.
 */
class TimelineEventDescription {

   String shortDesc;
   String mediumDesc;
   String fullDesc;

   TimelineEventDescription (String fullDescription, String medDescription, String shortDescription) {
	   this.shortDesc = shortDescription;
	   this.mediumDesc = medDescription;
	   this.fullDesc = fullDescription;
   }

   TimelineEventDescription (String fullDescription) {
	   this.shortDesc = "";
	   this.mediumDesc = "";
	   this.fullDesc = fullDescription;
   }


   /**
	* Get the full description of this event.
	*
	* @return the full description
	*/
   String getFullDescription() {
	   return fullDesc;
   }

   /**
	* Get the medium description of this event.
	*
	* @return the medium description
	*/
   String getMediumDescription() {
	   return mediumDesc;
   }

   /**
	* Get the short description of this event.
	*
	* @return the short description
	*/
   String getShortDescription() {
	   return shortDesc;
   }

   /**
	* Get the description of this event at the give level of detail(LoD).
	*
	* @param lod The level of detail to get.
	*
	* @return The description of this event at the given level of detail.
	*/
   String getDescription(TimelineEvent.DescriptionLevel lod) {
	   switch (lod) {
		   case FULL:
		   default:
			   return getFullDescription();
		   case MEDIUM:
			   return getMediumDescription();
		   case SHORT:
			   return getShortDescription();
	   }
   }
}

