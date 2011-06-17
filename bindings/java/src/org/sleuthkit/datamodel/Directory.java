package org.sleuthkit.datamodel;

import java.sql.SQLException;
import java.util.*;

/**
 *
 * @author alawrence
 */
public class Directory extends FsContent{
	
    /**
     * Contructor: most inputs are from the database
     * @param db java database structure
     * @param fs_id
     * @param file_id
     * @param attr_type
     * @param attr_id
     * @param name
     * @param par_file_id
     * @param dir_type
     * @param meta_type
     * @param dir_flags
     * @param meta_flags
     * @param size
     * @param ctime
     * @param crtime
     * @param atime
     * @param mtime
     * @param mode
     * @param uid
     * @param gid
     */
    protected Directory(Sleuthkit db, long fs_id, long file_id, long attr_type, long attr_id, String name, long par_file_id,
			long dir_type, long meta_type, long dir_flags, long meta_flags, long size, 
			long ctime, long crtime, long atime, long mtime, long mode, long uid, long gid) throws SQLException{
		this.db = db;
		this.fs_id = fs_id;
		this.file_id = file_id;
		this.attr_type = attr_type;
		this.attr_id = attr_id;
                this.name = name;
		this.par_file_id = par_file_id;
		this.dir_type = dir_type;
		this.meta_type = meta_type;
		this.dir_flags = dir_flags;
		this.meta_flags = meta_flags;
		this.size = size;
		this.ctime = ctime;
		this.crtime = crtime;
		this.atime = atime;
		this.mtime = mtime;
		this.mode = mode;
		this.uid = uid;
		this.gid = gid;
		childIds = db.getChildIds(file_id, fs_id);
		childNames = db.getChildNames(file_id, fs_id);

                /**
                 * If name is empty, it means we adding the root metadata. In
                 * this case, we add this to the child as well. We will change
                 * the name to "." on "getFile(fs_id, file_id, name)" method.
                 */
                if(name.equals("") && !childIds.contains(file_id)){
                    childIds.add(file_id);
                    childNames.add(name);
                }
	}
	
	private ArrayList<Long> childIds; //could use set or other structure
	private ArrayList<String> childNames;
	
        /**
         * is this a directory?
         * @return true, it is a directory
         */
    @Override
        public boolean isDir(){
		return true;
	}

        /**
         * gets all child files and directories of this directory
         * @return an arraylist of the children
         */
        public ArrayList<FsContent> getFiles() throws SQLException{
		ArrayList<FsContent> content = new ArrayList<FsContent>();
		for(int i = 0; i < childIds.size(); i++){
			FsContent file = db.getFile(fs_id, childIds.get(i), childNames.get(i));
			if (file != null /*&&!file.getName().equals(".")&&!file.getName().equals("..") */){
				file.setParent(parentFileSystem);
				content.add(file);
			}
		}
			return content;
	}
}
package org.sleuthkit.datamodel;

import java.sql.SQLException;
import java.util.*;

/**
 *
 * @author alawrence
 */
public class Directory extends FsContent{
	
    /**
     * Contructor: most inputs are from the database
     * @param db java database structure
     * @param fs_id
     * @param file_id
     * @param attr_type
     * @param attr_id
     * @param name
     * @param par_file_id
     * @param dir_type
     * @param meta_type
     * @param dir_flags
     * @param meta_flags
     * @param size
     * @param ctime
     * @param crtime
     * @param atime
     * @param mtime
     * @param mode
     * @param uid
     * @param gid
     */
    protected Directory(Sleuthkit db, long fs_id, long file_id, long attr_type, long attr_id, String name, long par_file_id,
			long dir_type, long meta_type, long dir_flags, long meta_flags, long size, 
			long ctime, long crtime, long atime, long mtime, long mode, long uid, long gid) throws SQLException{
		this.db = db;
		this.fs_id = fs_id;
		this.file_id = file_id;
		this.attr_type = attr_type;
		this.attr_id = attr_id;
                this.name = name;
		this.par_file_id = par_file_id;
		this.dir_type = dir_type;
		this.meta_type = meta_type;
		this.dir_flags = dir_flags;
		this.meta_flags = meta_flags;
		this.size = size;
		this.ctime = ctime;
		this.crtime = crtime;
		this.atime = atime;
		this.mtime = mtime;
		this.mode = mode;
		this.uid = uid;
		this.gid = gid;
		childIds = db.getChildIds(file_id, fs_id);
		childNames = db.getChildNames(file_id, fs_id);

                /**
                 * If name is empty, it means we adding the root metadata. In
                 * this case, we add this to the child as well. We will change
                 * the name to "." on "getFile(fs_id, file_id, name)" method.
                 */
                if(name.equals("") && !childIds.contains(file_id)){
                    childIds.add(file_id);
                    childNames.add(name);
                }
	}
	
	private ArrayList<Long> childIds; //could use set or other structure
	private ArrayList<String> childNames;
	
        /**
         * is this a directory?
         * @return true, it is a directory
         */
    @Override
        public boolean isDir(){
		return true;
	}

        /**
         * gets all child files and directories of this directory
         * @return an arraylist of the children
         */
        public ArrayList<FsContent> getFiles() throws SQLException{
		ArrayList<FsContent> content = new ArrayList<FsContent>();
		//if(childIds != null){
			for(int i = 0; i < childIds.size(); i++){
				FsContent file = db.getFile(fs_id, childIds.get(i), childNames.get(i));
				if (file != null /*&&!file.getName().equals(".")&&!file.getName().equals("..") */){
					file.setParent(parentFileSystem);
					content.add(file);
				}
				
			}
			return content;
		//}
		//else return content;
	}


	/*public long getSize() {
		// directory size
		return 0;
	}*/

}
