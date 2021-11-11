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
import java.util.ArrayList;
import java.util.List;

import org.sleuthkit.caseuco.Hash.HashMethod;

/**
 * This class definition mirrors the ContentDataFacet observable described in the UCO
 ontology.
 */
class ContentDataFacet extends Facet {

    @SerializedName("observable:sizeInBytes")
    private Long sizeInBytes;

    @SerializedName("observable:mimeType")   
    private String mimeType;

    @SerializedName("observable:hashs")
    private final List<Hash> hashes;

    @SerializedName("observable:dataPayload")
    private String dataPayload;

    @SerializedName("observable:owner")
    private String owner;
    
    @SerializedName("observable:dataPayloadReferenceUrl")
    private String dataPayloadReferenceUrl;

    ContentDataFacet() {
        super(ObservableObject.OBSERVABLE + ContentDataFacet.class.getSimpleName());
        this.hashes = new ArrayList<>();
    }

    ContentDataFacet setSizeInBytes(long bytes) {
        this.sizeInBytes = bytes;
        return this;
    }

    ContentDataFacet setMimeType(String mimeType) {
        this.mimeType = mimeType;
        return this;
    }

    ContentDataFacet setMd5Hash(String md5Hash) {
        Hash md5HashType = new Hash(md5Hash)
                .setHashMethod(HashMethod.MD5);
        hashes.add(md5HashType);
        return this;
    }

    ContentDataFacet setDataPayload(String dataPayload) {
        this.dataPayload = dataPayload;
        return this;
    }

    ContentDataFacet setOwner(Identity owner) {
        this.owner = owner.getId();
        return this;
    }
    
    ContentDataFacet setDataPayloadReferenceUrl(UcoObject url) {
        this.dataPayloadReferenceUrl = url.getId();
        return this;
    }

    Long getSizeInBytes() {
        return sizeInBytes;
    }

    String getMimeType() {
        return mimeType;
    }

    List<Hash> getHashes() {
        return hashes;
    }

    String getDataPayload() {
        return dataPayload;
    }

    String getOwner() {
        return owner;
    }

    String getDataPayloadReferenceUrl() {
        return dataPayloadReferenceUrl;
    }
}
