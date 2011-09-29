/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 * Interface for implementing a visitor pattern visitor for Content
 *
 * @param <T> return type of visit methods
 * @author pmartel
 */
public interface ContentVisitor<T> {
    
    T visit(Directory d);
    T visit(File f);
    T visit(FileSystem fs);
    T visit(Image i);
    T visit(Volume v);
    T visit(VolumeSystem vs);
	
	static abstract public class Default<T> implements ContentVisitor<T> {

		protected abstract T defaultVisit(Content c);
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
	}
    
}
