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

import com.google.gson.annotations.SerializedName;
import java.util.ArrayList;
import java.util.List;

import org.sleuthkit.caseuco.Hash.HashMethod;

/**
 * This class definition mirrors the ContentData observable described in the UCO
 * ontology.
 */
public class ContentData extends Facet {

    private Long sizeInBytes;

    private String mimeType;

    @SerializedName("hash")
    private final List<Hash> hashes;

    private String dataPayload;

    private String owner;
    
    private String dataPayloadReferenceUrl;

    ContentData() {
        super(ContentData.class.getSimpleName());
        this.hashes = new ArrayList<>();
    }

    public ContentData setSizeInBytes(long bytes) {
        this.sizeInBytes = bytes;
        return this;
    }

    public ContentData setMimeType(String mimeType) {
        this.mimeType = mimeType;
        return this;
    }

    public ContentData setMd5Hash(String md5Hash) {
        Hash md5HashType = new Hash(md5Hash)
                .setHashMethod(HashMethod.MD5);
        hashes.add(md5HashType);
        return this;
    }

    public ContentData setDataPayload(String dataPayload) {
        this.dataPayload = dataPayload;
        return this;
    }

    public ContentData setOwner(Identity owner) {
        this.owner = owner.getId();
        return this;
    }
    
    public ContentData setDataPayloadReferenceUrl(UcoObject url) {
        this.dataPayloadReferenceUrl = url.getId();
        return this;
    }

    public Long getSizeInBytes() {
        return sizeInBytes;
    }

    public String getMimeType() {
        return mimeType;
    }

    public List<Hash> getHashes() {
        return hashes;
    }

    public String getDataPayload() {
        return dataPayload;
    }

    public String getOwner() {
        return owner;
    }

    public String getDataPayloadReferenceUrl() {
        return dataPayloadReferenceUrl;
    }
}
