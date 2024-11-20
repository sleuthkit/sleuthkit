
#include "mult_files.h"

#include <iomanip>
#include <vector>

namespace {

// return non-zero if str ends with suffix, ignoring case
int endsWith(const TSK_TCHAR * str, const TSK_TCHAR * suffix) {
  return TSTRLEN(str) >= TSTRLEN(suffix) ?
    TSTRICMP(&str[TSTRLEN(str) - TSTRLEN(suffix)], suffix) == 0 : 0;
}

}

std::function<TSK_TSTRING(size_t, TSK_TOSTRINGSTREAM&)> getSegmentPattern(const TSK_TCHAR* first) {
  const size_t flen = TSTRLEN(first);

  // zero-padded numeric counter, zero- or one-based:
  // [.000,] .001, .002, ... ; [_000,] _001, _002, ...
  if (first[flen-1] == '0' || first[flen-1] == '1') {
    const bool zero_based = first[flen-1] == '0';

    // find left end of zero padding
    int i;
    for (i = flen - 2; i >= 0 && first[i] == '0'; --i) ;

    if (first[i] == '.' || first[i] == '_') {
      const TSK_TSTRING base(first, first + i + 1);
      const size_t width = flen - (i + 1);

      // NB: digit overflow is ok; FTK apparently adds a fourth digit
      // when there are > 999 segments.
      return [base, width, zero_based](size_t i, TSK_TOSTRINGSTREAM& os) {
        os << base << std::setfill(_TSK_T('0')) << std::setw(width)
           << (i+1-zero_based);
        return os.str();
      };
    }
  }
  // alphabetic counter:
  // .aaa, .aab, .aac, ... ; _aaa, _aab, _aac, ... ; xaaa, xaab, xaac, ...
  else if (first[flen-1] == 'a') {
    // find left end of suffix
    int i;
    for (i = flen - 2; i >= 0 && first[i] == 'a'; --i) ;

    if (first[i] == '.' || first[i] == '_' || first[i] == 'x') {
      const TSK_TSTRING base(first);
      const size_t limit = i;

      return [base, limit](size_t i, TSK_TOSTRINGSTREAM&) {
        TSK_TSTRING seg(base);
        for (size_t d = seg.size() - 1; i; i /= 26, --d) {
          if (d == limit) {
            // we've exhausted the counter width
            return TSK_TSTRING();
          }
          seg[d] = i % 26 + 'a';
        }
        return seg;
      };
    }
  }
  // .dmg: .dmg, .002.dmgpart, .003.dmgpart, ...
  else if (endsWith(first, _TSK_T(".dmg"))) {
    const TSK_TSTRING base(first, first + flen - 3);

    return [base](size_t i, TSK_TOSTRINGSTREAM& os) {
      os << base << std::setfill(_TSK_T('0')) << std::setw(3) << (i+1)
         << ".dmgpart";
      return os.str();
    };
  }
  // .bin: .bin, (2).bin, (3).bin, ...
  else if (endsWith(first, _TSK_T(".bin"))) {
    const TSK_TSTRING base(first, first + flen - 4);

    return [base](size_t i, TSK_TOSTRINGSTREAM& os) {
      os << base << '(' << (i+1) << ").bin";
      return os.str();
    };
  }

  // no pattern detected
  return nullptr;
}

namespace {

template <class T>
void free_array(T** a, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    free(a[i]);
  }
  free(a);
}

TSK_TCHAR** str_vec_to_array(const std::vector<TSK_TSTRING>& vec) {
  const size_t count = vec.size();

  TSK_TCHAR** arr = (TSK_TCHAR**) tsk_malloc(count * sizeof(TSK_TCHAR*));
  if (!arr) {
    return nullptr;
  }

  for (size_t i = 0; i < count; ++i) {
    const size_t len = vec[i].size() + 1;
    arr[i] = (TSK_TCHAR*) tsk_malloc(len * sizeof(TSK_TCHAR));
    if (!arr[i]) {
      free_array(arr, i);
      return nullptr;
    }
    TSTRNCPY(arr[i], vec[i].c_str(), len);
  }

  return arr;
}

bool add_if_exists(const TSK_TSTRING& name, std::vector<TSK_TSTRING>& names) {
  struct STAT_STR stat_buf;

  // does the file exist?
  if (TSTAT(name.c_str(), &stat_buf) < 0) {
    return false;
  }

  if (tsk_verbose) {
    tsk_fprintf(stderr, "tsk_img_findFiles: %" PRIttocTSK " found\n", name.c_str());
  }

  names.push_back(name);
  return true;
}

}

/**
 * @param a_startingName First name in the list (must be full name)
 * @param [out] a_numFound Number of images that are in returned list
 * @returns array of names that caller must free (NULL on error or if supplied file does not exist)
 */
TSK_TCHAR **
tsk_img_findFiles(const TSK_TCHAR * a_startingName, int *a_numFound)
{
  TSK_TCHAR** nlist = nullptr;
  std::vector<TSK_TSTRING> names;
  *a_numFound = 0;

  // get the first segment
  if (add_if_exists(a_startingName, names)) {
    // look for a pattern
    const auto pfunc = getSegmentPattern(a_startingName);
    if (pfunc) {
      // found a pattern, look for subsequent segments
      TSK_TOSTRINGSTREAM os;
      for (size_t i = 1; add_if_exists(pfunc(i, os), names); ++i, os.str(_TSK_T("")));
    }

    // copy the vector to a C array
    nlist = str_vec_to_array(names);
    if (nlist) {
      *a_numFound = names.size();
    }
  }

  if (tsk_verbose) {
    tsk_fprintf(stderr, "tsk_img_findFiles: %d total segments found\n", names.size());
  }
  return nlist;
}
