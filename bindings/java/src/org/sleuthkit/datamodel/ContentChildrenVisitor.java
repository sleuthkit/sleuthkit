/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package org.sleuthkit.datamodel;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

/**
 * ContentVisitor that returns the children Contents.
 *
 * @author pmartel
 */
public class ContentChildrenVisitor implements ContentVisitor<List<? extends Content>> {

    @Override
    public List<? extends Content> visit(Directory d) {
        try {
			List<FsContent> files = d.getFiles();
			
			
			// filter out the . and .. directories
			Iterator<FsContent> fileIter = files.iterator();
			
			long currentId = d.getFile_id();
			long parentId = d.getPar_file_id();
			
			while(fileIter.hasNext()) {
				long id = fileIter.next().getFile_id();
				if (id == currentId || id == parentId) {
					fileIter.remove();
				}
			}
			
            return files;
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public List<? extends Content> visit(File f) {
        return Collections.EMPTY_LIST;
    }

    @Override
    public List<? extends Content> visit(FileSystem fs) {
        try {
            return Collections.singletonList(fs.getRootDir());
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public List<? extends Content> visit(Image i) {
        try {
            return Collections.singletonList(i.getVolumeSystem(0));
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public List<? extends Content> visit(Volume v) {
        try {
			FileSystem fs = v.getFileSystem();
            return (fs != null) ? Collections.singletonList(fs) : Collections.EMPTY_LIST;
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public List<? extends Content> visit(VolumeSystem vs) {
        try {
            List<Long> volIds = vs.getVolIds();
            List<Volume> volumes = new ArrayList(volIds.size());
            for(long id: volIds) {
                volumes.add(vs.getVolume(id));
            }
            return volumes;
        } catch (SQLException ex) {
            throw new RuntimeException(ex);
        }
    }
}
