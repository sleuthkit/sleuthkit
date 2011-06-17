class TskAutoDbJNI:public TskAutoDb {
  public:
      bool m_cancelled;
      TskAutoDbJNI();
      virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file,
        const char *path);
      void cancelProcess();
};
class TskAutoDbJNI:public TskAutoDb {
  public:
      bool m_cancelled;
      TskAutoDbJNI();
      virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file,
        const char *path);
      void cancelProcess();
};