package org.sleuthkit.datamodel;

/**
 * Interface for all content from the sleuthkit.
 * @author alawrence
 */
public interface Content {

    /**
     * read data from the content in the sleuthkit
     * @param offset offset to start reading from
     * @param len amount of data to read (in bytes)
     * @return a character array of data (in bytes)
     */
    public byte[] read(long offset, long len) throws TskException;

    /**
     * get the size of the content
     * @return size of the content
     */
    public long getSize();
}
