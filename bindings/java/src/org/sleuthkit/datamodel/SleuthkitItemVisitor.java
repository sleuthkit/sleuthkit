/*
 * Autopsy Forensic Browser
 *
 * Copyright 2011-2018 Basis Technology Corp.
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
 * Interface for implementing a visitor pattern on all displayable items:
 * Content implementations and blackboard artifacts.
 *
 * Visitor implements an algorithm on the content and blackboard artifacts
 * objects. The algorithm is completely decoupled from the data object. The
 * visitor pattern emulates double dispatch mechanism. It allows to act
 * differently depending on the instance type, without need to test what the
 * actual type is. E.g. it allows for processing an object hierarchy without
 * using instanceof statements. Generic type parameter T is a return type from
 * the visit methods.
 *
 * @param <T> return type of visit methods
 */
public interface SleuthkitItemVisitor<T> {

	/**
	 * Act on (visit) a Directory content object
	 *
	 * @param d the directory to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(Directory d);

	/**
	 * Act on (visit) a File content object
	 *
	 * @param f the file to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(File f);

	/**
	 * Act on (visit) a FileSystem content object
	 *
	 * @param fs the filesystem to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(FileSystem fs);

	/**
	 * Act on (visit) an Image content object
	 *
	 * @param i the image to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(Image i);

	/**
	 * Act on (visit) a Volume content object
	 *
	 * @param v the volume to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(Volume v);

	/**
	 * Act on (visit) a VolumeSystem content object
	 *
	 * @param vs the volume system to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(VolumeSystem vs);

	/**
	 * Act on (visit) a blackboard artifact object
	 *
	 * @param ba blackboard artifact object to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(BlackboardArtifact ba);

	/**
	 * Act on (visit) a blackboard artifact type
	 *
	 * @param tw blackboard artifact type to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(BlackboardArtifact.ARTIFACT_TYPE tw);

	/**
	 * Act on (visit) a layout file content object
	 *
	 * @param lf layout file to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(LayoutFile lf);

	/**
	 * Act on (visit) a VirtualDirectory content object
	 *
	 * @param ld layout dir to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(VirtualDirectory ld);

	/**
	 * Act on (visit) a LocalDirectory content object
	 *
	 * @param ld layout dir to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(LocalDirectory ld);

	/**
	 * Act on (visit) a DerivedFile content object
	 *
	 * @param df derived file to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(DerivedFile df);

	/**
	 * Act on (visit) a LocalFile content object
	 *
	 * @param lf local file to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(LocalFile lf);

	/**
	 * Act on (visit) a SlackFile content object
	 *
	 * @param sf slack file to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(SlackFile sf);

	/**
	 * Act on (visit) a Report content object
	 *
	 * @param report report to visit / act on
	 *
	 * @return result of the visit
	 */
	T visit(Report report);

	/**
	 * The default visitor - quickest method for implementing a custom visitor.
	 * Every visit method delegates to the defaultVisit method, the only
	 * required method to be implemented. Then, implement the specific visit
	 * methods for the objects on which the algorithm needs to act differently.
	 *
	 * @param <T> generic type, signifies the object type to be returned from
	 *            visit()
	 */
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

		@Override
		public T visit(LayoutFile lf) {
			return defaultVisit(lf);
		}

		@Override
		public T visit(VirtualDirectory vd) {
			return defaultVisit(vd);
		}

		@Override
		public T visit(LocalDirectory ld) {
			return defaultVisit(ld);
		}

		@Override
		public T visit(DerivedFile df) {
			return defaultVisit(df);
		}

		@Override
		public T visit(LocalFile lf) {
			return defaultVisit(lf);
		}

		@Override
		public T visit(SlackFile sf) {
			return defaultVisit(sf);
		}

		@Override
		public T visit(Report report) {
			return defaultVisit(report);
		}
	}
}
