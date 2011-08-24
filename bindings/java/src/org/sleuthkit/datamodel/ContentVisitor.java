/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

/**
 * Interface for implementing a visitor pattern visitor for Content
 *
 * @author pmartel
 */
public interface ContentVisitor<T> {
    
    T visit(Directory d);
    T visit(File f);
    T visit(FileSystem fs);
    T visit(Image i);
    T visit(Volume v);
    T visit(VolumeSystem vs);
    
}
