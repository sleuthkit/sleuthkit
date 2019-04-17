/***************************************************************************
** This data and information is proprietary to, and a valuable trade secret
** of, Basis Technology Corp.  It is given in confidence by Basis Technology
** and may only be used as permitted under the license agreement under which
** it has been distributed, and in no other way.
**
** Copyright (c) 2014 Basis Technology Corp. All rights reserved.
**
** The technical data and information provided herein are provided with
** `limited rights', and the computer software provided herein is provided
** with `restricted rights' as those terms are defined in DAR and ASPR
** 7-104.9(a).
***************************************************************************/

#pragma once

#include <string>

using namespace std;

/*
 * Defines a high level threat that we report on. 
 * Each Rule may have one or more subrules that match
 * A total score for the threat is calculated by adding the scores of all subrules contribute to it.
 * 
 */
enum THREAT_CATEGORY
{
   CAT_NONE,
   CAT_RECYCLE_BIN_EXE,
   CAT_ALTERNATE_DATASTREAM_EXE,
   CAT_PACKED_EXE,
   CAT_ENCRYPTED_ARCHIVE,
   CAT_EXE_SIGNATURE,
   CAT_USER_LOGIN,
   CAT_USER_LOGIN_FAILURE,
   CAT_CRED_VALIDATION_FAILURE,
   CAT_SUSPICIOUS_REG_ENTRY,
   CAT_NETWORK_DRIVE_PROCESS,
   NUM_CATEGORIES     // define new categories above
};



/*
 * Each criteria is assigned a score
 */
namespace CRITERIA_SCORE {

	enum Enum {
        UNKNOWN,
        NONE,
		LOW,
		MEDIUM,
        HIGH
	};

	static char String[][100] = {
        "UNKNOWN",
        "NONE",
		"LOW",
		"MEDIUM",
        "HIGH"
	};
}

/*
 * A subrule defines a fine level condition to match. Each subrul has an associated score.
 */
enum THREAT_CRITERIA
{
   CR_NONE,
   CR_NONE_LOW,
   CR_NONE_MED,
   CR_NONE_HIGH,

   
   CR_PE_SUSPICIOUS_IMPORTS,                    // too few imports or imports tyical of packed exe
   CR_PE_SUSPICIOUS_CODE_SECTION_SIZE,          // code section size is 0
   CR_PE_SUSPICIOUS_SECTION_NAME,               // section name is suspicious - e.g. random chars, or blank string
   CR_PE_SECTIONNAME_UPX,                       // section name with substr UPX
   CR_PE_SECTIONNAME_MPRESS,                    // section name with substr MPRESS
   CR_PE_SECTIONNAME_PEC,                       // section name with substr PEC
   CR_PE_SECTIONNAME_MEW,                       // section name with substr MEW
   CR_PE_SECTIONNAME_RLPACK,                    // section name with substr RLPACK
   CR_PE_SECTIONNAME_ASPACK,                    // section name with substr ASPACK
   CR_PE_SECTIONNAME_PACKMAN,                   // section name with substr PACKMAN

  
   CR_EXE_NO_SIGNATURE,                         // EXE has no signature, or there is an error in finding one
   CR_EXE_UNTRUSTED_SIGNATURE,                  // EXE has a signature but is not trusted  -     
   CR_EXE_TRUSTED_SIGNATURE,                    // EXE has a sig and it is trusted
   CR_EXE_TRUSTED_MICROSOFT_SIGNATURE,			// Exe is signed by Microsoft
   CR_EXE_ERROR_SIGNATURE,                    // error confirming signature


   CR_REG_WINLOGON,                             // Denotes a specific type of suspicious registry
};


class ThreatCategory {
public:
    ThreatCategory(THREAT_CATEGORY aCat, string aName, string aDescr) : 
      m_cat(aCat),
      m_catName(aName),
      m_description(aDescr)
      {
      };
    ~ThreatCategory(void);

public:
   
    THREAT_CATEGORY getType() const { return m_cat; };
    string getCategoryName() const { return m_catName; };
    string getDescription() const { return m_description; };

private: 
    
    THREAT_CATEGORY m_cat;
    string m_catName;  
    string m_description;
};


class ThreatCriteria {

public:
    ThreatCriteria(THREAT_CRITERIA aType, string aName, CRITERIA_SCORE::Enum aScore, string aDescr) : 
        m_critType(aType),
        m_critName(aName),
        m_rawScore(aScore),
        m_description(aDescr)
    {
    };
    ~ThreatCriteria(void);

    THREAT_CRITERIA getType() const { return m_critType; };
    string getName() const { return m_critName; };
    string getDescription() const { return m_description; };
    CRITERIA_SCORE::Enum getScore() const  { return m_rawScore;};

private: 
    THREAT_CRITERIA m_critType;
    string m_critName;  
    CRITERIA_SCORE::Enum m_rawScore;
    string m_description;
};

