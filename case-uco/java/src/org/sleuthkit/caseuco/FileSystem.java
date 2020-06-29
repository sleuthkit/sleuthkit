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

import org.sleuthkit.datamodel.TskData;
import org.sleuthkit.datamodel.TskData.TSK_FS_TYPE_ENUM;

import static org.sleuthkit.datamodel.TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_EXT4;
import static org.sleuthkit.datamodel.TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_HFS;
import static org.sleuthkit.datamodel.TskData.TSK_FS_TYPE_ENUM.TSK_FS_TYPE_NTFS;

/**
 * This class definition mirrors the FileSystem observable described in the UCO
 * ontology.
 */
class FileSystem extends Facet {

    private FileSystemType fileSystemType;

    private Long cluserSize;

    FileSystem() {
        super(FileSystem.class.getSimpleName());
    }

    FileSystem setFileSystemType(TskData.TSK_FS_TYPE_ENUM fileSystemType) {
        this.fileSystemType = FileSystemType.from(fileSystemType);
        return this;
    }

    FileSystem setCluserSize(long cluserSize) {
        this.cluserSize = cluserSize;
        return this;
    }

    //Adapter for TSK_FS_TYPE enum
    private enum FileSystemType {
        BDE(null),
        CPIO(null),
        EXT4(TSK_FS_TYPE_EXT4),
        F2FS(null),
        HFS(TSK_FS_TYPE_HFS),
        LVM(null),
        NTFS(TSK_FS_TYPE_NTFS),
        SevenZ(null),
        TAR(null),
        VSSVolume(null),
        ZIP(null);

        private final TskData.TSK_FS_TYPE_ENUM tskType;

        private FileSystemType(TSK_FS_TYPE_ENUM tskType) {
            this.tskType = tskType;
        }

        private static FileSystemType from(TSK_FS_TYPE_ENUM typeToConvert) {
            for (FileSystemType type : FileSystemType.values()) {
                if (type.tskType == typeToConvert) {
                    return type;
                }
            }

            return null;
        }
    }
}
