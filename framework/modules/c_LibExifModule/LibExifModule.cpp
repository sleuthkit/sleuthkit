/*
 * The Sleuth Kit
 *
 * Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2011-2012 Basis Technology Corporation. All Rights
 * reserved.
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file ExifExtractModule.cpp 
 * Contains the implementation of the EXIF data extraction file analysis module.
 */

// System includes
#include <string>
#include <sstream>
#include <string.h>

// Framework includes
#include "tsk/framework/utilities/TskModuleDev.h"

// libexif includes
#include "libexif/exif-loader.h"

#include "Poco/DateTime.h"
#include "Poco/DateTimeParser.h"

namespace 
{
    const char *MODULE_NAME = "tskLibExifModule";
    const char *MODULE_DESCRIPTION = "Stores extracted EXIF data to the image database";
    const char *MODULE_VERSION = "1.0.0";

    // JFIF signature
    static unsigned char jfifSig[] = { 0xFF, 0xD8, 0xFF, 0xE0 };
    // EXIF signature
    static unsigned char exifSig[] = { 0xFF, 0xD8, 0xFF, 0xE1 };

    // We process the file 8k at a time
    static const uint32_t FILE_BUFFER_SIZE = 8192;

    std::map<ExifTag, TSK_ATTRIBUTE_TYPE> initializeTagMap()
    {
        std::map<ExifTag, TSK_ATTRIBUTE_TYPE> retval;

        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>(EXIF_TAG_MAKE, TSK_DEVICE_MAKE));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>(EXIF_TAG_MODEL, TSK_DEVICE_MODEL));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>((ExifTag)EXIF_TAG_GPS_LATITUDE, TSK_GEO_LATITUDE));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>((ExifTag)EXIF_TAG_GPS_LONGITUDE, TSK_GEO_LONGITUDE));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>((ExifTag)EXIF_TAG_GPS_ALTITUDE, TSK_GEO_ALTITUDE));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>((ExifTag)EXIF_TAG_GPS_MAP_DATUM, TSK_GEO_MAPDATUM));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>((ExifTag)EXIF_TAG_GPS_SPEED, TSK_GEO_VELOCITY));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>((ExifTag)EXIF_TAG_DATE_TIME_ORIGINAL, TSK_DATETIME));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>((ExifTag)EXIF_TAG_XP_AUTHOR, TSK_NAME_PERSON));
        retval.insert(pair<ExifTag, TSK_ATTRIBUTE_TYPE>((ExifTag)EXIF_TAG_TIME_ZONE_OFFSET,TSK_DATETIME));

        return retval;
    }

    static std::map<ExifTag, TSK_ATTRIBUTE_TYPE> tagMap = initializeTagMap();

    /**
     * Extracts GPS coordinates from the given tag_data and converts them
     * into decimal degrees.
     */
    float getDecimalDegrees(char * tag_data)
    {
        char * token;
        char * deg;
        char * min;
        char * sec;
        // Tokenize the data
        token = strtok(tag_data, " , ");
        // Caputure degrees, minutes, seconds
        if (token)
        {
            deg = token;
            token = strtok(NULL, " , ");
        }
        if (token)
        {
            min = token;
            token = strtok(NULL, " , ");
        }
        if (token)
        {
            sec = token;
            token = strtok(NULL, " , ");
        }
        // Formula to convert to decimal
        return (atof(deg) + (atof(min)/60) + (atof(sec)/3600));
    }

    /* Extracts GPS speed and returns speed as float value */
    float getGPSSpeed(char *tag_data)
    {
        char * token;
        char * wholeNum;
        char * decimal;
        // Tokenize the data
        token = strtok(tag_data, ".");
        //Get the whole number value
        if (token)
        {
            wholeNum = token;
            token = strtok(NULL, ".");
        }
        if (token)
        {
            decimal = token;
            token = strtok(NULL, " , ");
        }
        return (atof(wholeNum) + atof(decimal));
    }
}

extern "C" 
{
    /**
     * Module identification function. 
     *
     * @return The name of the module as a const char *.
     */
    TSK_MODULE_EXPORT const char* name()
    {
        return MODULE_NAME;
    }

    /**
     * Module identification function. 
     *
     * @return A description of the module as a const char *.
     */
    TSK_MODULE_EXPORT const char* description()
    {
        return MODULE_DESCRIPTION;
    }

    /**
     * Module identification function. 
     *
     * @return The version of the module as a const char *.
     */
    TSK_MODULE_EXPORT const char* version()
    {
        return MODULE_VERSION;
    }
    
    /* Function to populate TSK Blackboard exif related attributes */
    void extractExifData(ExifData * exifData, TskFile * pFile)
    {
        std::map<ExifTag, TSK_ATTRIBUTE_TYPE>::iterator it;
        std::vector<TskBlackboardAttribute> attrs;
        std::string datetime = "";
        int timezone = 0;

        for (it = tagMap.begin(); it != tagMap.end(); ++it)
        {
            ExifEntry * exifEntry = exif_data_get_entry(exifData, it->first);
            char tag_data[256];

            if (exifEntry == NULL)
                continue;

            if (it->first == EXIF_TAG_GPS_LATITUDE ||
                it->first == EXIF_TAG_GPS_LONGITUDE)
            {
                // Check for the EXIF_IFD_GPS image file directory to avoid interoperability value
                ExifIfd ifd = exif_entry_get_ifd(exifEntry);
                if (ifd != EXIF_IFD_GPS)
                    continue;

                exif_entry_get_value(exifEntry, tag_data, 256);

                float decDegrees = getDecimalDegrees(tag_data);

                char refValue[2];

                if (it->first == EXIF_TAG_GPS_LATITUDE)
                {
                    // Get the latitude reference value; used to determine if positive or negative decimal value
                    ExifEntry * latitudeRef = exif_data_get_entry(exifData, it->first);
                    exif_entry_get_value(latitudeRef, refValue,2);

                    if (strcmp(refValue, "S") == 0)
                        decDegrees *= -1;
                }
                else
                {
                    // Get the longitude reference value; used to determine if positive or negative decimal value
                    ExifEntry * longitudeRef = exif_data_get_entry(exifData, it->first);
                    exif_entry_get_value(longitudeRef, refValue,2);

                    if (strcmp(refValue, "W") == 0)
                        decDegrees *= -1;
                }
                
                TskBlackboardAttribute attr(it->second, name(), "", decDegrees);
                attrs.push_back(attr);                
            }
            else if (it->first == EXIF_TAG_GPS_SPEED)
            {
                // Check for the EXIF_IFD_GPS image file directory to avoid interoperability value
                ExifIfd ifd = exif_entry_get_ifd(exifEntry);
                if (ifd != EXIF_IFD_GPS)
                    continue;

                //Get the GPS speed value
                exif_entry_get_value(exifEntry, tag_data, 256);

                float speed = getGPSSpeed(tag_data);

                char refValue[2];

                //Get the GPS speed reference value
                ExifEntry * speedRef = exif_data_get_entry(exifData, it->first);
                exif_entry_get_value(speedRef, refValue,2);

                //Convert Kilometers per hour to meters per second 
                if (strcmp(refValue, "K") == 0)
                {
                     speed *= 0.277778;
                }
                //Convert Miles per hour to meters per second 
                if (strcmp(refValue, "M") == 0)
                {
                    speed *= 0.44704;
                }
                //Convert Knots to meters per second
                if (strcmp(refValue, "N") == 0)
                {
                    speed *= 0.514444;
                }
                
                TskBlackboardAttribute attr(it->second, name(), "", speed);
                attrs.push_back(attr);
            }
            else if (it->first == EXIF_TAG_DATE_TIME_ORIGINAL) 
            {
                exif_entry_get_value(exifEntry, tag_data, 256);
                datetime = std::string(tag_data);
            }
            else if(it->first == EXIF_TAG_TIME_ZONE_OFFSET){
                exif_entry_get_value(exifEntry, tag_data, 256);
                timezone = atoi(tag_data);
            }
            else
            {   
                // Get the tag's data
                exif_entry_get_value(exifEntry, tag_data, 256);

                // Add tag data to blackboard
                TskBlackboardAttribute attr(it->second, name(), "", tag_data);
                attrs.push_back(attr);
            }
        }
        if(!datetime.empty()){
            Poco::DateTime parsedDT;
            int tzd;
            Poco::DateTimeParser::tryParse(datetime, parsedDT, tzd);
            if(timezone)
                parsedDT.makeUTC(timezone);
            else
                parsedDT.makeUTC(tzd);
            TskBlackboardAttribute attr(TSK_DATETIME, name(), "", (uint64_t)parsedDT.utcTime());
            attrs.push_back(attr);
        }
        if(attrs.size() > 0){
            TskBlackboardArtifact art = pFile->createArtifact(TSK_METADATA_EXIF);
            for(size_t i = 0; i < attrs.size(); i++){
                art.addAttribute(attrs[i]);
            }
        }
    }

    /**
     * Module initialization function. This module does not take any arguments.

     * @return TskModule::OK
     */
    TskModule::Status TSK_MODULE_EXPORT initialize(const char* arguments)
    {
        return TskModule::OK;
    }

    /**
     * Module execution function. Receives a pointer to a file the module is to
     * process. The file is represented by a TskFile interface which is used
     * to read the contents of the file and post extracted EXIF data to the  
     * database.
     *
     * @param pFile A pointer to a file.
     * @returns TskModule::OK on success, TskModule::FAIL on error.
     */
    TskModule::Status TSK_MODULE_EXPORT run(TskFile * pFile) 
    {
        if (pFile == NULL) 
        {
            LOGERROR("ExifExtractModule: passed NULL file pointer.");
            return TskModule::FAIL;
        }

        try 
        {
            char buffer[FILE_BUFFER_SIZE];
            int bytesRead = 0;

            memset(buffer, 0, FILE_BUFFER_SIZE);
            bytesRead = pFile->read(buffer, FILE_BUFFER_SIZE);

            if (bytesRead < 4)
                return TskModule::OK;

            // Check the first 4 bytes to see if this is a JPEG file.
            // We check for both the JFIF and EXIF signatures.
            if (memcmp(buffer, jfifSig, sizeof(jfifSig)) != 0 &&
                memcmp(buffer, exifSig, sizeof(exifSig)) != 0)
            {
                // It's not a JPEG file so we skip it.
                return TskModule::OK;
            }

            ExifLoader * exifLoader = exif_loader_new();

            if (exifLoader == NULL)
            {
                LOGERROR("ExifExtractModule - Received NULL ExifLoader pointer");
                return TskModule::FAIL;
            }

            // Feed the file content into libexif
            while (bytesRead > 0)
            {
                exif_loader_write(exifLoader, reinterpret_cast<unsigned char *>(buffer), bytesRead);
                memset(buffer, 0, FILE_BUFFER_SIZE);
                bytesRead = pFile->read(buffer, FILE_BUFFER_SIZE);
            }

            ExifData * exifData = exif_loader_get_data(exifLoader);

            // exifData will be NULL if there is no EXIF data in the image
            if (exifData != NULL)
            {
                // For debugging, exif_data_dump writes all exif data to stdout
                //exif_data_dump(exifData);

                extractExifData(exifData, pFile);

                exif_data_unref(exifData);
            }

            // Free the loader
            exif_loader_unref(exifLoader);
        }
        catch (TskException& tskEx)
        {
            std::stringstream msg;
            msg << "ExifExtractModule - Error processing file id " << pFile->getId() << ": " << tskEx.message();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }
        catch (std::exception& ex)
        {
            std::stringstream msg;
            msg << "ExifExtractModule - Error processing file id " << pFile->getId() << ": " << ex.what();
            LOGERROR(msg.str());
            return TskModule::FAIL;
        }

        return TskModule::OK;
    }

    /**
     * Module cleanup function. This module does not need to free any 
     * resources allocated during initialization or execution.
     *
     * @returns TskModule::OK
     */
    TskModule::Status TSK_MODULE_EXPORT finalize()
    {
        return TskModule::OK;
    }
}
