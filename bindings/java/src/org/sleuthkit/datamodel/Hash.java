/*
 * Autopsy Forensic Browser
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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

class Hash {
    /**
     * generate the md5 hash for the given content
    */
    static String calculateHash(Content content){
        String hashText = "";
        try {
            MessageDigest md = MessageDigest.getInstance("md5");
            byte[] contentBytes = content.read(0, content.getSize());
            byte[] hash = md.digest(contentBytes);
            BigInteger bigInt = new BigInteger(1,hash);
            hashText = bigInt.toString(16);
            // zero padding
            while(hashText.length() < 32 ){
                hashText = "0"+hashText;
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(Hash.class.getName()).log(Level.SEVERE, "No algorithm known as 'md5'", ex);
        } catch (TskException ex) {
           Logger.getLogger(Hash.class.getName()).log(Level.SEVERE, "Error reading content", ex);
        }
        return hashText;
    }
}
