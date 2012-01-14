/*
 * Sleuth Kit Data Model
 *
 * Copyright 2011 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.sleuthkit.datamodel;

/**
 * Implements some general methods from the Content interface. 
 */
public abstract class AbstractContent implements Content {
	
	final protected SleuthkitCase db;
	final private long obj_id;

	AbstractContent(SleuthkitCase db, long obj_id) {
		this.db = db;
		this.obj_id = obj_id;
	}
	
	@Override
	public long getId() {
		return this.obj_id;
	}
    
    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AbstractContent other = (AbstractContent) obj;
        if (this.obj_id != other.obj_id) {
            return false;
        }
        return true;
    }
    
    @Override
    public int hashCode() {
        int hash = 7;
        hash = 41 * hash + (int) (this.obj_id ^ (this.obj_id >>> 32));
        return hash;
    }
	
}
