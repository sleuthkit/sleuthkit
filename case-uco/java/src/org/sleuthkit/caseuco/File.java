/*
 * Sleuth Kit CASE JSON LD Support
 *
 * Copyright 2020 Basis Technology Corp.
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

import java.time.Instant;
import java.time.ZoneOffset;

/**
 * This class definition mirrors the File observable described in the UCO
 * ontology.
 */
class File extends Facet {

    private String accessedTime;

    private String extension;

    private String fileName;

    private String filePath;

    private Boolean isDirectory;

    private Long sizeInBytes;

    File() {
        super(File.class.getSimpleName());
    }

    File setAccessedTime(Long accessedTime) {
        if (accessedTime != null) {
            this.accessedTime = Instant.ofEpochSecond(accessedTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    File setExtension(String extension) {
        this.extension = extension;
        return this;
    }

    File setFileName(String fileName) {
        this.fileName = fileName;
        return this;
    }

    File setFilePath(String filePath) {
        this.filePath = filePath;
        return this;
    }

    File setIsDirectory(boolean isDirectory) {
        this.isDirectory = isDirectory;
        return this;
    }

    File setSizeInBytes(long sizeInBytes) {
        this.sizeInBytes = sizeInBytes;
        return this;
    }
}
