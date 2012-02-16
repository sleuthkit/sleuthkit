/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2010-2011 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file TskBlackboardArtifact.h
 * Contains the definition for the TskBlackboardArtifact class.
 */
#ifndef _TSK_BLACKBOARD_ARTIFACT_H
#define _TSK_BLACKBOARD_ARTIFACT_H

#include <string>
#include <vector>
#include "framework_i.h"

using namespace std;

/**
 * Built in artifact types 
 */
typedef enum ARTIFACT_TYPE {
		TSK_ART_GEN_INFO = 1,
		TSK_ART_WEB_BOOKMARK,
		TSK_ART_WEB_COOKIE,
		TSK_ART_WEB_HISTORY,
		TSK_ART_WEB_DOWNLOAD,
		TSK_ART_RECENT_OBJECT,
		TSK_ART_TRACKPOINT,
		TSK_ART_INSTALLED_PROG,
		TSK_ART_KEYWORD_HIT
    };

class TskBlackboardAttribute;
class TskBlackboard;

/**
 * Class that represents a blackboard artifact object.
 */
class TSK_FRAMEWORK_API TskBlackboardArtifact
{
public:
	static string getTypeName(ARTIFACT_TYPE type);
	static string getDisplayName(ARTIFACT_TYPE type);
	
	virtual uint64_t getArtifactID();
	virtual uint64_t getObjectID();
    virtual int getArtifactTypeID();
    virtual string getArtifactTypeName();
    virtual string getDisplayName();
    virtual void addAttribute(TskBlackboardAttribute attr);
	virtual vector<TskBlackboardAttribute> getAttributes();	
	~TskBlackboardArtifact();
    TskBlackboardArtifact(TskBlackboard * blackboard, uint64_t artifactID, uint64_t objID, int artifactTypeID, string artifactTypeName, string displayName);
    TskBlackboardArtifact();

protected:
    virtual void setBlackboard(TskBlackboard * blackboard);

private:
	uint64_t m_artifactID;
	uint64_t m_objID;
	int m_artifactTypeID;
	string m_artifactTypeName;
	string m_displayName;	
    TskBlackboard * m_blackboard;
};
	
#endif