/*
 * Sleuth Kit CASE JSON LD Support
 *
 * Copyright 2020-2021 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	 http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.caseuco;

import com.google.gson.annotations.SerializedName;
import java.time.Instant;
import java.time.ZoneOffset;

/**
 * This class definition mirrors the FileFacet observable described in the UCO
 ontology.
 */
class FileFacet extends Facet {

    @SerializedName("observable:accessedTime")
    private String accessedTime;

    @SerializedName("observable:extension")
    private String extension;

    @SerializedName("observable:fileName")
    private String fileName;

    @SerializedName("observable:filePath")
    private String filePath;

    @SerializedName("observable:isDirectory")
    private Boolean isDirectory;

    @SerializedName("observable:sizeInBytes")
    private Long sizeInBytes;

    FileFacet() {
        super(UcoObject.UCO_OBSERV + FileFacet.class.getSimpleName());
    }

    FileFacet setAccessedTime(Long accessedTime) {
        if (accessedTime != null) {
            this.accessedTime = Instant.ofEpochSecond(accessedTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    FileFacet setExtension(String extension) {
        this.extension = extension;
        return this;
    }

    FileFacet setFileName(String fileName) {
        this.fileName = fileName;
        return this;
    }

    FileFacet setFilePath(String filePath) {
        this.filePath = filePath;
        return this;
    }

    FileFacet setIsDirectory(boolean isDirectory) {
        this.isDirectory = isDirectory;
        return this;
    }

    FileFacet setSizeInBytes(long sizeInBytes) {
        this.sizeInBytes = sizeInBytes;
        return this;
    }
    
    String getAccessedTime() {
        return accessedTime;
    }

    String getExtension() {
        return extension;
    }

    String getFileName() {
        return fileName;
    }

    String getFilePath() {
        return filePath;
    }

    Boolean getIsDirectory() {
        return isDirectory;
    }

    Long getSizeInBytes() {
        return sizeInBytes;
    }    
}
