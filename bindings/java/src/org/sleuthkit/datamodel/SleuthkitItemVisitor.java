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

/**
 * Interface for implementing a visitor pattern on all SleuthkitVisitableItem 
 * implementations.  Allows for processing a SleuthkitVisitableItem object 
 * without having to use lots of instanceof statements.
 *
 * @param <T> return type of visit methods
 */
public interface SleuthkitItemVisitor<T> {

    T visit(Directory d);
    T visit(File f);
    T visit(FileSystem fs);
    T visit(Image i);
    T visit(Volume v);
    T visit(VolumeSystem vs);
    T visit(BlackboardArtifact ba);
    T visit(BlackboardArtifact.ARTIFACT_TYPE tw);

    static abstract public class Default<T> implements SleuthkitItemVisitor<T> {

        protected abstract T defaultVisit(SleuthkitVisitableItem s);
        @Override
        public T visit(Directory d) {
            return defaultVisit(d);
        }

        @Override
        public T visit(File f) {
            return defaultVisit(f);
        }

        @Override
        public T visit(FileSystem fs) {
            return defaultVisit(fs);
        }

        @Override
        public T visit(Image i) {
            return defaultVisit(i);
        }

        @Override
        public T visit(Volume v) {
            return defaultVisit(v);
        }

        @Override
        public T visit(VolumeSystem vs) {
            return defaultVisit(vs);
        }

        @Override
        public T visit(BlackboardArtifact ba) {
            return defaultVisit(ba);
        }

        @Override
        public T visit(BlackboardArtifact.ARTIFACT_TYPE tw) {
            return defaultVisit(tw);
        }
    }
}
