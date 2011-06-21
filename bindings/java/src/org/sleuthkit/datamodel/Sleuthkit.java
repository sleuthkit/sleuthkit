package org.sleuthkit.datamodel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import org.sleuthkit.datamodel.TskData.TSK_FS_NAME_TYPE_ENUM;

/**
 * database connection object. makes use of the sqlite jdbc libraries
 * @author alawrence
 */
public class Sleuthkit {
	private String dbPath;
        private String imageDirectory;
	private Connection con;

        /**
         * constructor
         * @param path path to the database
         * @throws SQLException
         * @throws ClassNotFoundException
         */
        public Sleuthkit(String dbPath) throws SQLException, ClassNotFoundException{
	        Class.forName("org.sqlite.JDBC");
		this.dbPath = dbPath;
                int i = dbPath.length()-1;
                while(dbPath.charAt(i) != '\\' && dbPath.charAt(i) != '/'){
                    i--;
                }
                imageDirectory = dbPath.substring(0, i);
		con = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
                con.setReadOnly(true);
	}

        public Sleuthkit(String dbPath, String imageDirectory) throws SQLException, ClassNotFoundException{
                Class.forName("org.sqlite.JDBC");
                this.dbPath = dbPath;
                this.imageDirectory = imageDirectory;
                con = DriverManager.getConnection("jdbc:sqlite:" + dbPath);
        }

        public static void makeDb(String[] paths, String outDir) throws TskException{
            SleuthkitJNI.makeDb(paths, outDir);
        }

        /**
         * fill a new filesystem content object with data from the database. will
         * also check the database field to determine if it is a file or directory
         * @param fs_id file system id
         * @param file_id file id
         * @return a new FsContent object
         */
        public FsContent getFile(long fs_id, long file_id) throws SQLException{
		Statement statement;
			statement = con.createStatement();

			ResultSet rs = statement.executeQuery("select * from tsk_fs_files " +
					"where file_id = " + file_id +" and fs_id = " + fs_id);
			if(!rs.next()){
                                rs.close();
                                statement.close();
			        return null;
			}
			else
				if (rs.getLong("dir_type") == TSK_FS_NAME_TYPE_ENUM.TSK_FS_NAME_TYPE_DIR.getDirType()){
					Directory dir = new Directory(this, rs.getLong("fs_id"), rs.getLong("file_id"), rs.getLong("attr_type"),
							rs.getLong("attr_id"), rs.getString("name"), rs.getLong("par_file_id"), rs.getLong("dir_type"),
							rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
							rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
							rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"));
                                        rs.close();
                                        statement.close();
                                        return dir;
				}
				else{
					File file = new File(this, rs.getLong("fs_id"), rs.getLong("file_id"), rs.getLong("attr_type"),
							rs.getLong("attr_id"), rs.getString("name"), rs.getLong("par_file_id"), rs.getLong("dir_type"),
							rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
							rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
							rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"));
                                        rs.close();
                                        statement.close();
                                        return file;
				}
	}

        /**
         * fill a new filesystem content object with data from the database. will
         * also check the database field to determine if it is a file or directory
         * @param fs_id file system id
         * @param file_id file id
         * @param name file name (used to differentiate between directories by name
         * and . and .. directories
         * @return a new FsContent object
         */
        public FsContent getFile(long fs_id, long file_id, String name) throws SQLException{
            Statement statement;
            statement = con.createStatement();

            ResultSet rs = statement.executeQuery("select * from tsk_fs_files " +
                            "where file_id = " + file_id +" and fs_id = " + fs_id + " and name = \"" + name + "\"");
            if(!rs.next()){
                    rs.close();
                    statement.close();
                    return null;
            }
            else{
                String tempName = "";

                // if name is empty, it's the root metadata so need to change the name to "."
                if(name.equals("")){
                    tempName = ".";
                }
                else{
                    tempName = rs.getString("name");
                }

                if (rs.getLong("dir_type") == TSK_FS_NAME_TYPE_ENUM.TSK_FS_NAME_TYPE_DIR.getDirType()){
                        Directory dir = new Directory(this, rs.getLong("fs_id"), rs.getLong("file_id"), rs.getLong("attr_type"),
                                        rs.getLong("attr_id"), tempName, rs.getLong("par_file_id"), rs.getLong("dir_type"),
                                        rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
                                        rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
                                        rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"));
                        rs.close();
                        statement.close();
                        return dir;
                }
                else{
                        File file = new File(this, rs.getLong("fs_id"), rs.getLong("file_id"), rs.getLong("attr_type"),
                                        rs.getLong("attr_id"), rs.getString("name"), rs.getLong("par_file_id"), rs.getLong("dir_type"),
                                        rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
                                        rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
                                        rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"));
                        rs.close();
                        statement.close();
                        return file;
                }
            }
	}

        /**
         * get the name and parent of the file/directory with the given id
         * @param fs_id filesystem id
         * @param file_id file id
         * @return array of length 2 with the name and parent id
         * @throws SQLException
         */
        public String[] getFsContentNameAndParent(long fs_id, long file_id) throws SQLException{
            Statement statement;
            statement = con.createStatement();

            ResultSet rs = statement.executeQuery("select name, par_file_id from tsk_fs_files " +
                            "where file_id = " + file_id +" and fs_id = " + fs_id);
            if(!rs.next()){
                String[] result = {"", "0"};
                return result;
            }
            else{
                String[] result = {rs.getString("name"), Long.toString(rs.getLong("par_file_id"))};
                return result;
            }
        }

        /**
         * fills a new file system object with data from the database
         * @param vol_id the volume to get the filesystem from
         * @return a new file system object
         */
        public FileSystem getFileSystem(long vol_id) throws SQLException{
		Statement statement;
			statement = con.createStatement();

			ResultSet rs = statement.executeQuery("select * from tsk_fs_info " +
					"where vol_id = " + vol_id);
			if(!rs.next()){
                                rs.close();
                                statement.close();
				return null;
			}
			else{
				FileSystem fs = new FileSystem(this, rs.getLong("fs_id"), rs.getLong("img_offset"), rs.getLong("vol_id"),
						rs.getLong("fs_type"), rs.getLong("block_size"), rs.getLong("block_count"),
                                                rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum"));
                                rs.close();
                                statement.close();
                                return fs;
            }
	}

        /**
         * Gets a new file system object with data from the database
         * @param fs_id  the FileSystem ID to get the filesystem from
         * @return fs    a new file system object
         */
        public FileSystem getFileSystemFromID(long fs_id) throws SQLException{
            Statement statement = con.createStatement();
            ResultSet rs = statement.executeQuery("select * from tsk_fs_info " +
                                    "where fs_id = " + fs_id);
            if(!rs.next()){
                rs.close();
                statement.close();
                return null;
            }
            else{
                FileSystem fs = new FileSystem(this, rs.getLong("fs_id"), rs.getLong("img_offset"), rs.getLong("vol_id"),
                                    rs.getLong("fs_type"), rs.getLong("block_size"), rs.getLong("block_count"),
                                    rs.getLong("root_inum"), rs.getLong("first_inum"), rs.getLong("last_inum"));
                return fs;
            }
	}

        /**
         * fills a new volume object from the database
         * @param vol_id volume id
         * @return new volume object
         */
        public Volume getVolume(long vol_id) throws SQLException{
            //get volume info from the database
            Statement statement;
            statement = con.createStatement();

            ResultSet rs = statement.executeQuery("select * from tsk_vs_parts " +
                            "where vol_id = " + vol_id);
            if(!rs.next()){
                rs.close();
                statement.close();
                return null;
            }
            else{
                Volume vol = new Volume(this, rs.getLong("vol_id"), rs.getLong("start"), rs.getLong("length"),
                                rs.getLong("flags"), rs.getString("desc"));
                rs.close();
                statement.close();
                return vol;
            }
	}

        /**
         * fills a new volume system object from the database
         * @param offset offset to the volume system
         * @return a new volume system object
         */
        public VolumeSystem getVolumeSystem(long offset) throws SQLException{
            Statement statement;
            ArrayList<Long> vol_ids = new ArrayList<Long>();
            statement = con.createStatement();

            ResultSet rs = statement.executeQuery("select * from tsk_vs_info " +
                            "where img_offset = " + offset);
            if(!rs.next()){
                rs.close();
                statement.close();
                return null;
            }
            else{
                long type = rs.getLong("vs_type");
                long imgOffset = rs.getLong("img_offset");
                long blockSize = rs.getLong("block_size");
                rs = statement.executeQuery("select vol_id from tsk_vs_parts");
                if(!rs.next()){
                        rs.close();
                        statement.close();
                        return null;
                }
                else{
                        do{
                                vol_ids.add(new Long(rs.getLong("vol_id")));
                        }while(rs.next());
                }
                VolumeSystem vs = new VolumeSystem(this, type, imgOffset, blockSize,
                                vol_ids);
                rs.close();
                statement.close();
                return vs;
            }
	}

        /**
         * get the name of this volume (based on the volume id)
         * @param fs_id file system
         * @return string with the name
         * @throws SQLException
         */
        public String getVolName(long fs_id) throws SQLException{
            Statement statement;
            ArrayList<Long> vol_ids = new ArrayList<Long>();
            statement = con.createStatement();

            ResultSet rs = statement.executeQuery("select vol_id from tsk_fs_info " +
                            "where fs_id = " + fs_id);
            if(!rs.next()){
                return null;
            }
            else{
                return "vol" + rs.getLong("vol_id");
            }
        }

        /**
         * fills a new image object with data from the database
         * @param imagePath path to the image
         * @return a new image object
         */
        public Image getImage() throws TskException, SQLException{
		//get image info from the database
		Statement statement;
		long type, ssize;
		String name;
                ArrayList<String> names = new ArrayList<String>();
			statement = con.createStatement();

			ResultSet rs = statement.executeQuery("select * from tsk_image_info");
			if(!rs.next()){
                                rs.close();
                                statement.close();
				return null;
			}
			else{
				type = rs.getLong("type");
				ssize = rs.getLong("ssize");
			}
			rs = statement.executeQuery("select * from tsk_image_names");
			if(!rs.next()){
                                rs.close();
                                statement.close();
				return null;
			}
			else{
                            name = rs.getString("name");
                            do{
				names.add(imageDirectory + "\\" + rs.getString("name"));
                            }while(rs.next());
				
			}

			Image img = new Image(this, type, ssize, name, names.toArray(new String[names.size()]));
                        rs.close();
                        statement.close();
                        return img;
	}

        /**
         * searches the database for files whose parent is the given file
         * @param dir_id directory id
         * @param fs_id file system to search
         * @return an arraylist of file ids
         */
        public ArrayList<Long> getChildIds(long dir_id, long fs_id) throws SQLException{
			Statement statement = con.createStatement();
			ArrayList<Long> childIds = new ArrayList<Long>();
			ResultSet rs = statement.executeQuery("SELECT file_id FROM tsk_fs_files " +
				"WHERE fs_id = " + fs_id + " AND par_file_id = " + dir_id);
			if(!rs.next()){
                                rs.close();
                                statement.close();
				return childIds;
			}
			else{
                            do{
                                    childIds.add(rs.getLong("file_id"));
                            }while(rs.next());
			}
                        rs.close();
                        statement.close();
			return childIds;
	}


        /**
         * get the names of the child files and directories. important for differentiating
         * between directories and . and .. directories
         * @param dir_id directory id
         * @param fs_id file system to search
         * @return an arraylist of names
         */
        public ArrayList<String> getChildNames(long dir_id, long fs_id) throws SQLException {
			Statement statement = con.createStatement();
			ArrayList<String> childIds = new ArrayList<String>();
			ResultSet rs = statement.executeQuery("SELECT name FROM tsk_fs_files " +
				"WHERE fs_id = " + fs_id + " AND par_file_id = " + dir_id);
			if(!rs.next()){
                                rs.close();
                                statement.close();
				return childIds;
			}
			else{
                            do{
                                    childIds.add(rs.getString("name"));
                            }while(rs.next());
			}
                        rs.close();
                        statement.close();
			return childIds;
	}
        
        /**
         * fill a new filesystem content object with data from the database. will
         * also check the database field to determine if it is a file or directory
         * @param fs_id file system id
         * @param file_id file id
         * @param name file name (used to differentiate between directories by name
         * and . and .. directories
         * @return a new FsContent object
         */
        public ArrayList<FsContent> resultSetToObjects(ResultSet rs, Image img) throws SQLException{
            ArrayList<FsContent> result = new ArrayList<FsContent>();
            FileSystem fs;

            if(!rs.next()){
                    return result;
            }
            else{
                Hashtable map = new Hashtable();

                do{
                    Long fsid = rs.getLong("fs_id");
                    if(map.containsKey(fsid)){
                        fs = (FileSystem)map.get(fsid);
                    }
                    else{
                    // Set all the parents for the FsContent
                    fs = this.getFileSystemFromID(fsid);
                    Volume vol = this.getVolume(fs.getVol_id());
                    VolumeSystem vs = this.getVolumeSystem(0); // usually the offset is 0, change it when needed
                    vs.setParent(img);
                    vol.setParent(vs);
                    fs.setParent(vol);
                    map.put(fsid, fs);
                    }

                    if (rs.getLong("dir_type") == TSK_FS_NAME_TYPE_ENUM.TSK_FS_NAME_TYPE_DIR.getDirType()){
                        Directory temp =  new Directory(this, rs.getLong("fs_id"), rs.getLong("file_id"), rs.getLong("attr_type"),
                                                rs.getLong("attr_id"), rs.getString("name"), rs.getLong("par_file_id"), rs.getLong("dir_type"),
                                                rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
                                                rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
                                                rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"));
                        temp.setParent(fs);
                        result.add(temp);
                    }
                    else{
                        File temp =  new File(this, rs.getLong("fs_id"), rs.getLong("file_id"), rs.getLong("attr_type"),
                                                rs.getLong("attr_id"), rs.getString("name"), rs.getLong("par_file_id"), rs.getLong("dir_type"),
                                                rs.getLong("meta_type"), rs.getLong("dir_flags"), rs.getLong("meta_flags"), rs.getLong("size"),
                                                rs.getLong("ctime"), rs.getLong("crtime"), rs.getLong("atime"), rs.getLong("mtime"),
                                                rs.getLong("mode"), rs.getLong("uid"), rs.getLong("gid"));
                        temp.setParent(fs);
                        result.add(temp);
                    }
                }
                while(rs.next());
            }
            return result;
	}

        /**
         * Returns the ResultSet from the given query.
         *
         * @param query  the given string query to run
         * @return rs    the resultSet
         * @throws SQLException
         */
        public ResultSet runQuery(String query) throws SQLException{
            Statement statement;
            statement = con.createStatement();

            ResultSet rs = statement.executeQuery(query);
            return rs;
	}

	public void finalize(){
		try
	      {
	        if(con != null)
	          con.close();
	      }
	      catch(SQLException e)
	      {
	        // connection close failed.
	        System.err.println(e);
	      }
	}

        /**
         * Closes the connection of this class.
         */
        public void closeConnection(){
		try
	      {
	        if(con != null)
	          con.close();
	      }
	      catch(SQLException e)
	      {
	        // connection close failed.
	        System.err.println(e);
	      }
	}
}
