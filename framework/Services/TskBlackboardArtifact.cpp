/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

#include <string>
#include <vector>
#include "framework_i.h"
#include "TskBlackboard.h"
#include "TskBlackboardAttribute.h"
#include "Utilities/TskException.h"
		
/**
 * Get type name for the given built in type
 * @param type artifact type 
 * @returns artifact type name
 */
string TskBlackboardArtifact::getTypeName(ARTIFACT_TYPE type) {
    switch(type){
        case TSK_ART_GEN_INFO:
            return "TSK_ART_GEN_INFO";
            break;
        case TSK_ART_WEB_BOOKMARK:
            return "TSK_ART_WEB_BOOKMARK";
            break;
        case TSK_ART_WEB_COOKIE:
            return "TSK_ART_WEB_COOKIE";
            break;

        case  TSK_ART_WEB_HISTORY:
            return "TSK_ART_WEB_HISTORY";
            break;

        case TSK_ART_WEB_DOWNLOAD:
            return "TSK_ART_WEB_DOWNLOAD";
            break;

        case TSK_ART_RECENT_OBJECT:
            return "TSK_ART_RECENT_OBJECT";
            break;

        case TSK_ART_TRACKPOINT:
            return "TSK_ART_TRACKPOINT";
            break;

        case TSK_ART_INSTALLED_PROG:
            return "TSK_ART_INSTALLED_PROG";
            break;

        case TSK_ART_KEYWORD_HIT:
            return "TSK_ART_KEYWORD_HIT";
            break;
        default:
            throw TskException("No Enum with that value"); 
    }
}

/**
 * Get display name for the given built in type
 * @param type artifact type 
 * @returns artifact display name
 */
string TskBlackboardArtifact::getDisplayName(ARTIFACT_TYPE type) {
    switch(type){
        case TSK_ART_GEN_INFO:
            return "General Info";
            break;
        case TSK_ART_WEB_BOOKMARK:
            return "Date Time";
            break;
        case TSK_ART_WEB_COOKIE:
            return "Web Cookie";
            break;

        case  TSK_ART_WEB_HISTORY:
            return "History";
            break;

        case TSK_ART_WEB_DOWNLOAD:
            return "Download";
            break;

        case TSK_ART_RECENT_OBJECT:
            return "Recent History Object";
            break;

        case TSK_ART_TRACKPOINT:
            return "Trackpoint";
            break;

        case TSK_ART_INSTALLED_PROG:
            return "Installed Program";
            break;

        case TSK_ART_KEYWORD_HIT:
            return "Keyword Hit";
            break;
        default:
            throw TskException("No Enum with that value"); 
    }
}

/**
 * Default destructor
 */
TskBlackboardArtifact::~TskBlackboardArtifact(){

}

/**
 * Get the artifact type id
 * @returns artifact type id
 */
uint64_t TskBlackboardArtifact::getArtifactID(){
    return m_artifactID;
}

/**
 * Get the object id
 * @returns object id
 */
uint64_t TskBlackboardArtifact::getObjectID(){
    return m_objID;
}

/**
 * Get the artifact type id
 * @returns artifact type id
 */
int TskBlackboardArtifact::getArtifactTypeID(){
    return m_artifactTypeID;
}

/**
 * Get the artifact type name
 * @returns artifact type name
 */
string TskBlackboardArtifact::getArtifactTypeName(){
    return m_artifactTypeName;
}

/**
 * Get the display name
 * @returns display name
 */
string TskBlackboardArtifact::getDisplayName(){
    return m_displayName;
}

/**
 * Add an attribute to this artifact
 * @param attr attribute to be added
 */
void TskBlackboardArtifact::addAttribute(TskBlackboardAttribute attr){
    attr.setArtifactID(m_artifactID);
    attr.setBlackboard(m_blackboard);
    m_blackboard->addBlackboardAttribute(attr);
}

/**
 * Get all attributes associated with this artifact
 * @returns a vector of attributes
 */
vector<TskBlackboardAttribute> TskBlackboardArtifact::getAttributes(){

    char whereClause[100];
    _snprintf_s(whereClause, 100, _TRUNCATE,
        "WHERE artifact_id = %d" ,
        m_artifactID);

    return m_blackboard->getMatchingAttributes(whereClause);
}

/**
 * Constructor
 * @param blackboard blackboard used to create this 
 * @param artifactID artifact id 
 * @param objID object id 
 * @param artifactTypeID arifact type id 
 * @param artifactTypeName artifact type name
 * @param displayName display name
 */	
TskBlackboardArtifact::TskBlackboardArtifact(TskBlackboard * blackboard, uint64_t artifactID, uint64_t objID, int artifactTypeID, string artifactTypeName, string displayName){
    m_artifactID = artifactID;
    m_objID = objID;
    m_artifactTypeID = artifactTypeID;
    m_artifactTypeName = artifactTypeName;
    m_displayName = displayName;
    m_blackboard = blackboard;
}

/**
 * Set the blackboard to write to
 * @param blackboard blackboard used to write to
 */
void TskBlackboardArtifact::setBlackboard(TskBlackboard * blackboard){
    m_blackboard = blackboard;
}

/**
 * Default constructor
 */
TskBlackboardArtifact::TskBlackboardArtifact(){}