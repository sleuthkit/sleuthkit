#include "tools/util.h"
#include "tsk/base/tsk_os.h"

#include <cstdio>
#include <cstdlib>

std::pair<
  std::unique_ptr<TSK_TCHAR*[], void(*)(TSK_TCHAR**)>,
  int
>
#ifdef TSK_WIN32
argv_to_tsk_tchar(int argc, char**) {
  // On Windows, get the wide arguments (mingw doesn't support wmain)
  std::unique_ptr<TSK_TCHAR*[], void(*)(TSK_TCHAR**)> args{
    CommandLineToArgvW(GetCommandLineW(), &argc),
    [](TSK_TCHAR** v) { LocalFree(v); }
  };
  
  if (!args) {
    std::fprintf(stderr, "Error getting wide arguments\n");
    std::exit(1);
  }

  return { std::move(args), argc };
#else
argv_to_tsk_tchar(int argc, char** argv) {
  // Pass argv, argc through when not on Windows
  return {
    std::unique_ptr<TSK_TCHAR*[], void(*)(TSK_TCHAR**)>{
      argv,
      [](TSK_TCHAR**){}
    },
    argc
  };
#endif
}
