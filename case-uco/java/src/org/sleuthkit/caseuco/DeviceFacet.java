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

/**
 * This class definition mirrors the DeviceFacet observable described in the UCO
 ontology.
 */
class DeviceFacet extends Facet {

    @SerializedName("observable:manufacturer")
    private String manufacturer;

    @SerializedName("observable:model")
    private String model;

    @SerializedName("observable:serialNumber")
    private String serialNumber;

    DeviceFacet() {
        super(DeviceFacet.class.getSimpleName());
    }

    DeviceFacet setManufacturer(String manufacturer) {
        this.manufacturer = manufacturer;
        return this;
    }

    DeviceFacet setModel(String model) {
        this.model = model;
        return this;
    }

    @Override
    DeviceFacet setId(String id) {
        super.setId("_:" + id);
        return this;
    }

    DeviceFacet setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    String getManufacturer() {
        return manufacturer;
    }

    String getModel() {
        return model;
    }

    String getSerialNumber() {
        return serialNumber;
    }
}
