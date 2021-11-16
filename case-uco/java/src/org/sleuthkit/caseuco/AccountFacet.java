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
 * This class definition mirrors the AccountFacet observable described in the UCO
 ontology.
 */
class AccountFacet extends Facet {

    @SerializedName("observable:accountType")
    private String accountType;

    @SerializedName("observable:accountIdentifier")
    private String accountIdentifier;

    @SerializedName("observable:owner")
    private String owner;

    AccountFacet() {
        super(UcoObject.UCO_OBSERV + AccountFacet.class.getSimpleName());
    }

    AccountFacet setAccountType(String accountType) {
        this.accountType = accountType;
        return this;
    }

    AccountFacet setAccountIdentifier(String accountIdentifier) {
        this.accountIdentifier = accountIdentifier;
        return this;
    }

    AccountFacet setOwner(Identity owner) {
        this.owner = owner.getId();
        return this;
    }

    String getAccountType() {
        return accountType;
    }

    String getAccountIdentifier() {
        return accountIdentifier;
    }

    String getOwner() {
        return owner;
    }
}
