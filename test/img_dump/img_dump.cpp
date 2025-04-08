#include "tsk/libtsk.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <stack>
#include <string>

#ifdef TSK_WIN32
#include <cwchar>
#include <locale>
#endif

std::string replace(
  const std::string& src,
  const std::string& find,
  const std::string& repl)
{
  std::string s(src);

  size_t pos = 0;
  while ((pos = s.find(find, pos)) != std::string::npos) {
    s.replace(pos, find.length(), repl);
    pos += repl.length();
  }

  return s;
}

// quotes and backslashes in JSON strings must be quoted with backslashes
std::string quote(const std::string& s) {
  return replace(replace(s, "\\", "\\\\"), "\"", "\\\"");
}

template <class Itr>
struct Hex {
  Itr beg, end;
};

// Write out bytes as hexidecimal
template <class Itr>
std::ostream& operator<<(std::ostream& out, Hex<Itr> h) {
  out << '"' << std::hex << std::setfill('0');
  for (auto i = h.beg; i != h.end; ++i) {
    out << std::setw(2) << static_cast<unsigned int>(*i);
  }
  out << std::dec << '"';
  return out;
}

std::string extractString(const char* buf, size_t len) {
// TODO: use string_view
  // chop off trailing nulls
  return buf ? std::string(buf, std::min(std::strlen(buf), len)) : "";
}

class JSON {
public:
  JSON(std::ostream& out): out(out), state() {}

  ~JSON() {
    while (!state.empty()) {
      end();
    }
  }

  JSON& obj() {
    if (!state.empty() && state.top().first[0] == ']') {
      sep();
    }
    out << '{';
    state.emplace("}", true);
    return *this;
  }

  // Open object to appear on its own line, for readable diffs
  JSON& obj_line() {
    if (!state.empty() && state.top().first[0] == ']') {
      sep();
    }
    nl();
    out << '{';
    state.emplace("}", true);
    return *this;
  }

  JSON& arr() {
    if (!state.empty() && state.top().first[0] == ']') {
      sep();
    }
    out << '[';
    state.emplace("]", true);
    return *this;
  }

  // Open array of objects to appear on their own lines, for readable diffs
  JSON& arr_lines() {
    if (!state.empty() && state.top().first[0] == ']') {
      sep();
    }
    out << '[';
    state.emplace("\n]", true);
    return *this;
  }

  JSON& end() {
    out << state.top().first;
    state.pop();
    return *this;
  }

  JSON& nl() {
    out << '\n';
    return *this;
  }

  JSON& k(const char* k) {
    sep();
    key(k);
    return *this;
  }

  template <class V>
  JSON& kv(const char* k, V v) {
    sep();
    key(k);
    value(v);
    return *this;
  }

  template <class V>
  JSON& v(V v) {
    sep();
    value(v);
    return *this;
  }

private:
  void sep() {
    if (state.top().second) {
      state.top().second = false;
    }
    else {
      out << ", ";
    }
  }

  void key(const char* k) {
    value(k);
    out << ": ";
  }

  void value(const std::string& v) {
    out << '"' << quote(v) << '"';
  }

  void value(char* v) {
    value(const_cast<const char*>(v));
  }

  void value(const char* v) {
    value(std::string(v));
  }

#ifdef TSK_WIN32
  void value(wchar_t* v) {
    value(const_cast<const wchar_t*>(v));
  }

  void value(const wchar_t* v) {
    auto len = std::wcslen(v);
    std::string s(len, '\0');
    auto& f = std::use_facet<std::ctype<wchar_t>>(std::locale());
    f.narrow(v, v + len, '?', &s[0]);
    value(s);
  }
#endif

  template <class V>
  void value(V v) {
    out << v;
  }

  std::ostream& out;
  std::stack<std::pair<std::string, bool>> state;
};

class Walker: public TskAuto {
public:
  Walker(std::ostream& out):
    TskAuto(),
    json(out),
    prev_vs_part(nullptr),
    prev_fs(nullptr) {}

  virtual ~Walker() {}

  void run() {
    auto img = m_img_info;

    json.obj();
    json.k("files");

    json.arr();
    for (auto i = 0; i < img->num_img; ++i) {
      json.v(img->images[i]);
    }
    json.end();

    json
      .kv("itype", tsk_img_type_toname(img->itype))
      .kv("desc", tsk_img_type_todesc(img->itype))
      .kv("size", img->size)
      .kv("sector_size", img->sector_size);

    findFilesInImg();
  }

  virtual TSK_FILTER_ENUM filterPool([[maybe_unused]] const TSK_POOL_INFO* p) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterPoolVol([[maybe_unused]] const TSK_POOL_VOLUME_INFO* pv) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterVs(const TSK_VS_INFO* vs) override {
    json.k("volumesystem");
    json.obj();

    json
      .kv("vstype", tsk_vs_type_toname(vs->vstype))
      .kv("desc", tsk_vs_type_todesc(vs->vstype))
      .kv("block_size", vs->block_size)
      .kv("part_count", vs->part_count)
      .kv("offset", vs->offset);

    json.k("volumes");
    json.arr();

    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO* vs_part) override {
    // We track the previous partition and fs so we know when they're finished
    // because TskAuto presently has no end callbacks.
    if (prev_vs_part) {
      if (prev_fs) {
        json.end().end();
        prev_fs = nullptr;
      }
      json.end();
    }
    prev_vs_part = vs_part;

    json.obj();
    json
      .kv("addr", vs_part->addr)
      .kv("desc", vs_part->desc)
      .kv("flags", vs_part->flags)
      .kv("len", vs_part->len)
      .kv("slot_num", static_cast<int>(vs_part->slot_num))
      .kv("start", vs_part->start)
      .kv("table_num", static_cast<int>(vs_part->table_num));

    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO* fs) override {
    // We track the previous fs so we know when it's finished
    // because TskAuto presently has no end callbacks.
    if (prev_fs) {
      json.nl().end().end();
    }
    prev_fs = fs;

    json.k("filesystem");
    json.obj();
    json
      .kv("block_count", fs->block_count)
      .kv("block_size", fs->block_size)
      .kv("dev_bsize", fs->dev_bsize)
      .kv("duname", fs->duname)
      .kv("endian", fs->endian)
      .kv("first_block", fs->first_block)
      .kv("first_inum", fs->first_inum)
      .kv("flags", fs->flags)
      .kv("fs_id", Hex<const uint8_t*>{fs->fs_id, fs->fs_id + fs->fs_id_used})
      .kv("ftype", tsk_fs_type_toname(fs->ftype))
      .kv("journ_inum", fs->journ_inum)
      .kv("inum_count", fs->inum_count)
      .kv("last_block", fs->last_block)
      .kv("last_block_act", fs->last_block_act)
      .kv("last_inum", fs->last_inum)
      .kv("offset", fs->offset)
      .kv("root_inum", fs->root_inum);

    json.k("files");
    json.arr();

    return TSK_FILTER_CONT;
  }

  void processAttrRun(const TSK_FS_ATTR_RUN* r) {
    json.obj();
    json
      .kv("addr", r->addr)
      .kv("flags", r->flags)
      .kv("len", r->len)
      .kv("offset", r->offset);
    json.end();
  }

  void processAttr(const TSK_FS_ATTR* a) {
    json.obj();

    json
      .kv("flags", a->flags)
      .kv("id", a->id)
      .kv("type", a->type)
      .kv("name", extractString(a->name, a->name_size))
      .kv("size", a->size)
      .kv("rd_buf_size", a->rd.buf_size)
      .kv("nrd_allocsize", a->nrd.allocsize)
      .kv("nrd_compsize", a->nrd.compsize)
      .kv("nrd_initsize", a->nrd.initsize)
      .kv("nrd_skiplen", a->nrd.skiplen);

    if ((a->flags & TSK_FS_ATTR_RES) && a->rd.buf_size && a->rd.buf) {
      const size_t len = std::min(a->rd.buf_size, static_cast<size_t>(a->size));
      json.kv("rd_buf", Hex<const uint8_t*>{a->rd.buf, a->rd.buf + len});
    }

    if (a->flags & TSK_FS_ATTR_NONRES) {
      json.k("nrd_runs");
      json.arr();

      for (TSK_FS_ATTR_RUN* r = a->nrd.run; r; r = r->next) {
        if (r->flags == TSK_FS_ATTR_RUN_FLAG_FILLER) {
          continue;
        }
        processAttrRun(r);
      }

      json.end();
    }

    json.end();
  }

  void processName(const TSK_FS_NAME* name) {
    json.k("name");
    json.obj();

    json
      .kv("flags", name->flags)
      .kv("meta_addr", name->meta_addr)
      .kv("meta_seq", name->meta_seq)
      .kv("name", extractString(name->name, name->name_size))
      .kv("par_addr", name->par_addr)
      .kv("par_seq", name->par_seq)
      .kv("shrt_name", extractString(name->shrt_name, name->shrt_name_size))
      .kv("type", name->type);

    json.end();
  }

  void processMeta(const TSK_FS_META* meta, TSK_FS_FILE* file) {
    json.k("meta");
    json.obj();

    json
      .kv("addr", meta->addr)
      .kv("atime", meta->atime)
      .kv("atime_nano", meta->atime_nano)
      .kv("crtime", meta->crtime)
      .kv("crtime_nano", meta->crtime_nano)
      .kv("ctime", meta->ctime)
      .kv("ctime_nano", meta->ctime_nano)
      .kv("flags", meta->flags)
      .kv("gid", meta->gid);

    const auto fs = file->fs_info;

    if (TSK_FS_TYPE_ISEXT(fs->ftype)) {
      json
        .kv("dtime", meta->time2.ext2.dtime)
        .kv("dtime_nano", meta->time2.ext2.dtime_nano);
    }
    else if (TSK_FS_TYPE_ISHFS(fs->ftype)) {
      json
        .kv("bkup_time", meta->time2.hfs.bkup_time)
        .kv("bkup_time_nano", meta->time2.hfs.bkup_time_nano);
    }

    json
      .kv("mode", meta->mode)
      .kv("mtime", meta->mtime)
      .kv("mtime_nano", meta->mtime_nano)
      .kv("nlink", meta->nlink)
      .kv("seq", meta->seq)
      .kv("size", meta->size)
      .kv("type", meta->type)
      .kv("uid", meta->uid);

    const auto defAttr = tsk_fs_file_attr_get(file);
    json.kv("default_attr", defAttr ? defAttr->id : -1);

    json.k("attrs");
    json.arr_lines();

    if (meta->attr && (meta->attr_state & TSK_FS_META_ATTR_STUDIED)) {
      uint32_t i = 0;
      for (const TSK_FS_ATTR* a = meta->attr->head; a; a = a->next, ++i) {
        if (a->flags & TSK_FS_ATTR_INUSE) {
          processAttr(a);
        }
      }
    }
    else {
      const int numAttrs = tsk_fs_file_attr_getsize(file);
      if (numAttrs > 0) {
        for (int i = 0; i < numAttrs; ++i) {
          const TSK_FS_ATTR* a = tsk_fs_file_attr_get_idx(file, i);
          if (a && a->flags & TSK_FS_ATTR_INUSE) {
            processAttr(a);
          }
        }
      }
    }

    json.end();
    json.end();
  }

  virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE* file, const char*) override {
    json.obj_line();

    if (file->name) {
      processName(file->name);
    }

    if (file->meta) {
      processMeta(file->meta, file);
    }

    json.end();
    return TSK_OK;
  }

private:
  JSON json;
  const TSK_VS_PART_INFO* prev_vs_part;
  const TSK_FS_INFO* prev_fs;
};

int main(int argc, char** argv) {
  // Usage: img_dump IMAGE_PATH
  if (argc < 2) {
    return 1;
  }

  std::unique_ptr<TSK_IMG_INFO, void(*)(TSK_IMG_INFO*)> img{
    tsk_img_open_utf8(argc - 1, argv + 1, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };

  if (!img) {
    return 1;
  }

  Walker walker(std::cout);
  walker.openImageHandle(img.get());
  walker.run();

  return 0;
}
