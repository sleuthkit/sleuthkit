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
package org.sleuthkit.uco.observable;

import java.time.Instant;
import java.time.ZoneOffset;

import org.sleuthkit.uco.core.Facet;

public class File extends Facet {

    private String accessedTime;

    private String extension;

    private String fileName;

    private String filePath;

    private Boolean isDirectory;

    private Long sizeInBytes;

    public File() {
        super(File.class.getSimpleName());
    }

    public File setAccessedTime(Long accessedTime) {
        if(accessedTime != null) {
            this.accessedTime = Instant.ofEpochSecond(accessedTime).atOffset(ZoneOffset.UTC).toString();
        }
        return this;
    }

    public File setExtension(String extension) {
        this.extension = extension;
        return this;
    }

    public File setFileName(String fileName) {
        this.fileName = fileName;
        return this;
    }

    public File setFilePath(String filePath) {
        this.filePath = filePath;
        return this;
    }

    public File setIsDirectory(boolean isDirectory) {
        this.isDirectory = isDirectory;
        return this;
    }

    public File setSizeInBytes(long sizeInBytes) {
        this.sizeInBytes = sizeInBytes;
        return this;
    }
}
