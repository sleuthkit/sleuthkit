/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel.blackboardutils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.lang3.StringUtils;
import org.sleuthkit.datamodel.AbstractFile;
import org.sleuthkit.datamodel.Blackboard;
import org.sleuthkit.datamodel.BlackboardArtifact;
import org.sleuthkit.datamodel.BlackboardAttribute;
import org.sleuthkit.datamodel.SleuthkitCase;
import org.sleuthkit.datamodel.TskCoreException;


/**
 * Helper class to help module modules create artifacts.
 *
 * This class helps ingest modules create miscellaneous artifacts.
 * 
 */
public final class ArtifactsHelper extends AbstractArtifactHelper {
	private static final Logger logger = Logger.getLogger(ArtifactsHelper.class.getName());

	
	/**
	 * Creates an artifact helper for artifacts.
	 * 
	 * @param caseDb Sleuthkit case db
     * @param moduleName name module using the helper
     * @param srcFile source file
	 * 
	 */
	public ArtifactsHelper(SleuthkitCase caseDb, String moduleName, AbstractFile srcFile) {
		super(caseDb, moduleName, srcFile);
	}
	
	
	
	
	/**
     * Adds a TSK_GPS_TRACKPOINT artifact.
     * 
      * @param latitude location latitude, required
     * @param longitude location longitude, required
     * @param timeStamp date/time trackpoint recorded, can be 0 if not available
     * @param name trackpoint name, can be empty/null if not available
     * @param programName name of program that recorded trackpoint , can be empty or null if not available
     * 
     * @return artifact added
     */
    public BlackboardArtifact addGPSLocation(double latitude, double longitude, 
            long timeStamp, String name, String programName) {
        
        return addGPSLocation(latitude, longitude, timeStamp, name, programName,
                Collections.<BlackboardAttribute>emptyList());
    }
    
    /**
     * Adds a TSK_GPS_TRACKPOINT artifact.
     * 
     * @param latitude location latitude, required
     * @param longitude location longitude, required
     * @param timeStamp date/time trackpoint recorded, can be 0 if not available
     * @param name trackpoint name, can be empty/null if not available
     * @param programName name of program that recorded trackpoint , can be empty or null if not available
     * @param otherAttributesList other attributes, can be empty list of no additional attributes
     * 
     * @return artifact added
     */
    public BlackboardArtifact addGPSLocation(double latitude, double longitude, long timeStamp, String name, String programName, 
            Collection<BlackboardAttribute> otherAttributesList) {
       
        BlackboardArtifact gpsTrackpointArtifact = null;
        try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();
			
            // Create artifact
            gpsTrackpointArtifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_GPS_TRACKPOINT);
			
            
            // Add basic attributes 
            attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LATITUDE, getModuleName(), latitude));
            attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_GEO_LONGITUDE, getModuleName(), longitude));
            if (timeStamp > 0) {
                attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, getModuleName(), timeStamp));
            }
            
            if (!StringUtils.isEmpty(name)) {
                attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NAME, getModuleName(), name));
            }
            
            if (!StringUtils.isEmpty(programName)) {
                attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
            }
                            
            // add the attributes 
			gpsTrackpointArtifact.addAttributes(attributes);
			gpsTrackpointArtifact.addAttributes(otherAttributesList);
            
            // post artifact 
            getSleuthkitCase().getBlackboard().postArtifact(gpsTrackpointArtifact, getModuleName());
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Unable to add GPS trackpoint artifact", ex); //NON-NLS
            return null;
        } 
        catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((gpsTrackpointArtifact != null)? gpsTrackpointArtifact.getArtifactID() : "")), ex);  //NON-NLS
        }
        
        // return the artifact
        return gpsTrackpointArtifact;              
    }
	
	 /**
     * Adds a TSK_INSTALLED_PROGRAM artifact
     * 
     * @param programName name of program 
     * @param dateInstalled date of install
     * 
     * @return artifact added
     */
    public BlackboardArtifact addInstalledProgram(String programName, long dateInstalled) {
        return addInstalledProgram(programName, dateInstalled,
                Collections.<BlackboardAttribute>emptyList() );
    }
    
    /**
     * Adds a TSK_INSTALLED_PROGRAM artifact
     * 
     * @param programName name of program , required
     * @param dateInstalled date of install, can be 0 if not available
     * @param otherAttributesList additional attributes, can be an empty list if no additional attributes
     * 
     * @return artifact added
     */
    public BlackboardArtifact addInstalledProgram(String programName, long dateInstalled, 
            Collection<BlackboardAttribute> otherAttributesList ) {
        
        BlackboardArtifact installedProgramArtifact = null;
        try {
			Collection<BlackboardAttribute> attributes = new ArrayList<>();
			
            // Create artifact
            installedProgramArtifact = getAbstractFile().newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INSTALLED_PROG);
            
            // Add basic attributes 
            attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME, getModuleName(), programName));
            if (dateInstalled > 0) {
                attributes.add(new BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME, getModuleName(), dateInstalled));
            }
                            
            // Add attributes to artifact
            installedProgramArtifact.addAttributes(attributes);
			installedProgramArtifact.addAttributes(otherAttributesList);
			
            // post artifact 
            getSleuthkitCase().getBlackboard().postArtifact(installedProgramArtifact, getModuleName());
        } catch (TskCoreException ex) {
            logger.log(Level.SEVERE, "Unable to add installed program artifact", ex); //NON-NLS
            return null;
        } 
        catch (Blackboard.BlackboardException ex) {
            logger.log(Level.SEVERE, String.format("Unable to post artifact %s", ((installedProgramArtifact != null)? installedProgramArtifact.getArtifactID() : "")), ex);  //NON-NLS
        }
        
        // return the artifact
        return installedProgramArtifact;
    }
	
}
