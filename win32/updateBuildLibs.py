#!/usr/bin/python
#
# Copyright (c) 2017 Basis Technology.
#
# This software is distributed under the Common Public License 1.0
"""Script to help build the SleuthKit."""

from __future__ import print_function
from __future__ import unicode_literals

import argparse
import logging
import os
import subprocess
import shutil
import sys
import time


class BuildHelper(object):
  """SleuthKit build helper.

  Attributes:
    platform (str): name of the platform.
  """
  PLATFORM_CYGWIN = 'cygwin'
  PLATFORM_LINUX = 'linux'
  PLATFORM_MACOS = 'macos'
  PLATFORM_WINDOWS = 'windows'

  _BUILD_PATH = 'C:\\Projects'

  # (name, environment_variable, default_path)
  _LIBYAL_BUILD_TARGETS = [
      ('libewf', 'LIBEWF_HOME', os.path.join(_BUILD_PATH, 'libewf_64bit')),
      ('libvhdi', 'LIBVHDI_HOME', os.path.join(_BUILD_PATH, 'libvhdi_64bit')),
      ('libvmdk', 'LIBVMDK_HOME', os.path.join(_BUILD_PATH, 'libvmdk_64bit'))]

  _LIBYAL_REPO_URLS = {
      'libewf': 'https://github.com/libyal/libewf-legacy.git',
      'libvhdi': 'https://github.com/libyal/libvhdi.git',
      'libvmdk': 'https://github.com/libyal/libvmdk.git'}

  _SLEUTHKIT_LIBYAL_REPO_URLS = {
      'libewf': 'https://github.com/sleuthkit/libewf_64bit.git',
      'libvhdi': 'https://github.com/sleuthkit/libvhdi_64bit.git',
      'libvmdk': 'https://github.com/sleuthkit/libvmdk_64bit.git'}

  _TSK_BUILD_CONFIGURATIONS = [
      'Release', 'Release_NoLibs', 'Release_PostgreSQL']

  _TSK_BUILD_PLATFORMS = [
      'Win32', 'x64']

  _VSTOOLS_PATH = os.path.join(_BUILD_PATH, 'vstools')
  _VSTOOLS_REPO_URL = 'https://github.com/libyal/vstools.git'

  def __init__(self):
    """Initializes a SleuthKit build helper."""
    current_path = os.getcwd()
    log_filename = time.strftime('%Y.%m.%d-%H.%M.%S')
    log_path = os.path.join(current_path, 'output', log_filename)

    if not os.path.exists(log_path):
      os.makedirs(log_path)

    super(BuildHelper, self).__init__()
    self._current_path = current_path
    self._log_path = log_path
    self._msbuild_path = ''

    if sys.platform == "cygwin":
      self.platform = self.PLATFORM_CYGWIN
    elif sys.platform == "darwin":
      self.platform = self.PLATFORM_MACOS
    elif sys.platform in ("linux", "linux2"):
      self.platform = self.PLATFORM_LINUX
    elif sys.platform == "win32":
      self.platform = self.PLATFORM_WINDOWS

  def _BuildLibyalDependency(
      self, name, solution_path, project_name, platform):
    """Builds a libyal dependency.

    Args:
      name (str): name of the libyal dependency.
      solution_path (str): path of the Visual Studio solution.
      project_name (str): name of the Visual Studio project to build.
      platform (str): build platform, such as Win32 or x64.

    Returns:
      bool: True if successful or False otherwise.
    """
    configuration = 'Release'

    logging.info('Building %s as %s', name, platform)

    project_file_path = os.path.join(
        solution_path, project_name, '%s.vcxproj' % project_name)

    call = [
        self._msbuild_path,
        project_file_path,
        '/property:Configuration=%s,Platform=%s' % (configuration, platform),
        '/property:PlatformToolset=v140',
        '/target:Clean,Build']

    if 'APPVEYOR' in os.environ:
      # TODO: currently not working as intended, determine why.
      # call.append(
      #     '/logger:"C:\\Program Files\\AppVeyor\\BuildAgent\\'
      #     'Appveyor.MSBuildLogger.dll"')
      pass

    else:
      log_file = os.path.join(
          self._log_path, '%s-%s-msbuild.log' % (name, platform))
      call.append(
          '/logger:FileLogger,Microsoft.Build.Engine;logfile=%s' % log_file)

    logging.info(' '.join(call))
    exit_code = subprocess.call(call)
    if exit_code != 0:
      logging.info('Failed to build %s as %s', name, platform)
      return False

    logging.info('Successfully build %s as %s', name, platform)
    return True

  def _BuildTSK(self, configuration, platform):
    """Builds the SleuthKit in a specific configurations.

    Args:
      configuration (str): name of the build configuration.
      platform (str): build platform, such as Win32 or x64.

    Returns:
      bool: True if successful or False otherwise.
    """
    logging.info('Building TSK %s as %s', configuration, platform)

    solution_file = os.path.join('win32', 'tsk-win.sln')

    call = [
        self._msbuild_path,
        solution_file,
        '/property:Configuration=%s,Platform=%s' % (configuration, platform),
        '/target:Clean,Build']

    if 'APPVEYOR' in os.environ:
      # TODO: currently not working as intended, determine why.
      # call.append(
      #     '/logger:"C:\\Program Files\\AppVeyor\\BuildAgent\\'
      #     'Appveyor.MSBuildLogger.dll"')
      pass

    else:
      log_file = os.path.join(
          self._log_path, 'libtsk-%s-%s-msbuild.log' % (
              configuration, platform))
      call.append(
          '/logger:FileLogger,Microsoft.Build.Engine;logfile=%s' % log_file)

    logging.info(' '.join(call))
    exit_code = subprocess.call(call)
    if exit_code != 0:
      logging.error('Failed to build TSK %s as %s', configuration, platform)
      return False

    logging.info('Successfully build TSK %s as %s', configuration, platform)
    return True

  def _DownloadAndBuildLibyalDependencyDLL(self, name, path, platform):
    """Downloads and builds a 32 and 64-bit DLL of a libyal dependency.

    Args:
      name (str): name of the dependency.
      path (str): path to the sources of the dependency.
      platform (str): build platform, such as Win32 or x64.

    Returns:
      bool: True if successful or False otherwise.
    """
    repo_url = self._SLEUTHKIT_LIBYAL_REPO_URLS.get(name, None)
    if not repo_url:
      logging.warning('Missing git repository URL for: %s', name)
      return False

    if not os.path.exists(path):
      logging.warning('No such path: %s', path)
      return False

    # Work-around for old naming convention.
    if name == 'libewf':
      project_name = 'libewf_dll'
    else:
      project_name = name

    if not self._GitPull(path, repo_url, 'master'):
      return False

    solution_path = os.path.join(path, 'msvscpp')

    # pylint: disable=redefined-argument-from-local
    if platform:
      platforms = [platform]
    else:
      platforms = self._TSK_BUILD_PLATFORMS

    for platform in platforms:
      if not self._BuildLibyalDependency(
          name, solution_path, project_name, platform):
        return False

    # Make sure the .lib and .dll files are in the path where TSK expects them.
    if 'Win32' in platforms:
      win32_dll_path = os.path.join(path, 'msvscpp', 'Release')
      if not os.path.exists(win32_dll_path):
        os.makedirs(win32_dll_path)

      dll_path = os.path.join(
          solution_path, project_name, 'Release', 'Win32',
          '%s.dll' % name)
      shutil.copy(dll_path, win32_dll_path)

      # TODO: determine why this check is needed.
      # The new DLL should not be 2 mins old.
      ctime = time.time() - 2 * 60
      if not os.path.exists(dll_path) or os.path.getctime(dll_path) < ctime:
        logging.info('Missing DLL: %s', dll_path)
        return False

      lib_path = os.path.join(
          solution_path, project_name, 'Release', 'Win32',
          '%s.lib' % name)
      shutil.copy(lib_path, win32_dll_path)

      dll_path = os.path.join(
          solution_path, 'zlib', 'Release', 'Win32', 'zlib.dll')
      if os.path.exists(dll_path):
        shutil.copy(dll_path, win32_dll_path)

      lib_path = os.path.join(
          solution_path, 'zlib', 'Release', 'Win32', 'zlib.lib')
      if os.path.exists(lib_path):
        shutil.copy(lib_path, win32_dll_path)

    if 'x64' in platforms:
      x64_dll_path = os.path.join(path, 'msvscpp', 'x64', 'Release')
      if not os.path.exists(x64_dll_path):
        os.makedirs(x64_dll_path)

      dll_path = os.path.join(
          solution_path, project_name, 'x64', 'Release',
          '%s.dll' % name)
      shutil.copy(dll_path, x64_dll_path)

      # TODO: determine why this check is needed.
      # The new DLL should not be 2 mins old.
      ctime = time.time() - 2 * 60
      if not os.path.exists(dll_path) or os.path.getctime(dll_path) < ctime:
        logging.info('Missing DLL: %s', dll_path)
        return False

      lib_path = os.path.join(
          solution_path, project_name, 'x64', 'Release',
          '%s.lib' % name)
      shutil.copy(lib_path, x64_dll_path)

      dll_path = os.path.join(
          solution_path, 'zlib', 'x64', 'Release', 'zlib.dll')
      if os.path.exists(dll_path):
        shutil.copy(dll_path, x64_dll_path)

      lib_path = os.path.join(
          solution_path, 'zlib', 'x64', 'Release', 'zlib.lib')
      if os.path.exists(lib_path):
        shutil.copy(lib_path, x64_dll_path)

    return True

  def _DownloadAndBuildLibyalDependencyDLLWithVstools(
      self, name, path, platform):
    """Downloads and builds a 32 and 64-bit DLL of a libyal dependency.

    Args:
      name (str): name of the dependency.
      path (str): path to the sources of the dependency.
      platform (str): build platform, such as Win32 or x64.

    Returns:
      bool: True if successful or False otherwise.
    """
    repo_url = self._LIBYAL_REPO_URLS.get(name, None)
    if not repo_url:
      logging.warning('Missing git repository URL for: %s', name)
      return False

    if not os.path.exists(path) and not self._GitClone(repo_url, path):
      return False

    if not self._GitCheckoutLastestTaggedVersion(repo_url, path):
      return False

    if not self._PrepareBuildLibyalDependency(name, path):
      return False

    solution_path = os.path.join(path, 'vs2015')

    # pylint: disable=redefined-argument-from-local
    if platform:
      platforms = [platform]
    else:
      platforms = self._TSK_BUILD_PLATFORMS

    for platform in platforms:
      if not self._BuildLibyalDependency(name, solution_path, name, platform):
        return False

    # Make sure the .lib and .dll files are in the path where TSK expects them.
    if 'Win32' in platforms:
      win32_dll_path = os.path.join(path, 'msvscpp', 'Release')
      if not os.path.exists(win32_dll_path):
        os.makedirs(win32_dll_path)

      dll_path = os.path.join(
          solution_path, name, 'Release', 'Win32', '%s.dll' % name)
      shutil.copy(dll_path, win32_dll_path)

      lib_path = os.path.join(
          solution_path, name, 'Release', 'Win32', '%s.lib' % name)
      shutil.copy(lib_path, win32_dll_path)

      dll_path = os.path.join(
          solution_path, 'zlib', 'Release', 'Win32', 'zlib.dll')
      if os.path.exists(dll_path):
        shutil.copy(dll_path, win32_dll_path)

      lib_path = os.path.join(
          solution_path, 'zlib', 'Release', 'Win32', 'zlib.lib')
      if os.path.exists(lib_path):
        shutil.copy(lib_path, win32_dll_path)

    if 'x64' in platforms:
      x64_dll_path = os.path.join(path, 'msvscpp', 'x64', 'Release')
      if not os.path.exists(x64_dll_path):
        os.makedirs(x64_dll_path)

      dll_path = os.path.join(
          solution_path, name, 'Release', 'x64', '%s.dll' % name)
      shutil.copy(dll_path, x64_dll_path)

      lib_path = os.path.join(
          solution_path, name, 'Release', 'x64', '%s.lib' % name)
      shutil.copy(lib_path, x64_dll_path)

      dll_path = os.path.join(
          solution_path, 'zlib', 'Release', 'x64', 'zlib.dll')
      if os.path.exists(dll_path):
        shutil.copy(dll_path, x64_dll_path)

      lib_path = os.path.join(
          solution_path, 'zlib', 'Release', 'x64', 'zlib.lib')
      if os.path.exists(lib_path):
        shutil.copy(lib_path, x64_dll_path)

    return True

  def _GitCheckoutLastestTaggedVersion(self, repo_url, path):
    """Checks out the latest tagged version.

    Args:
      repo_url (str): URL of the repository.
      path (str): path the sources were cloned into.

    Returns:
      bool: True if successful or False otherwise.
    """
    logging.info('Checking out latest tagged version from %s', repo_url)

    call = ['git', 'fetch', '--all', '--tags', '--prune']
    logging.info(' '.join(call))
    exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
    if exit_code != 0:
      return False

    call = ['git', 'describe', '--tags', '--abbrev=0']
    logging.info(' '.join(call))

    process = subprocess.Popen(
        call, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=path)
    if process.returncode != 0:
      logging.info('Unable to checkout latest tag from %s.', repo_url)

      call = ['git', 'pull']
      logging.info(' '.join(call))
      exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
      if exit_code != 0:
        return False

      return True

    output, _ = process.communicate()
    tag = output.split('\n')[0]

    logging.info('Checking out %s', tag)

    call = ['git', 'checkout', 'tags/%s' % tag]
    logging.info(' '.join(call))
    exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
    if exit_code != 0:
      logging.info('Checkout of latest tag from %s failed.', repo_url)
      return False

    logging.info('Checkout of latest tag from %s successfully.', repo_url)
    return True

  def _GitClone(self, repo_url, path):
    """Clones the git repository into a specific directory.

    Args:
      repo_url (str): URL of the repository to clone.
      path (str): path of destination directory to clone into.

    Returns:
      bool: True if successful or False otherwise.
    """
    logging.info('Cloning %s into %s', repo_url, path)

    call = ['git', 'clone', repo_url, path]
    logging.info(' '.join(call))
    exit_code = subprocess.call(call, stdout=sys.stdout)
    if exit_code != 0:
      logging.info('Clone of %s failed.', repo_url)
      return False

    logging.info('Clone of %s successfully.', repo_url)
    return True

  def _GitPull(self, path, repo, branch):
    """Downloads the latest version of the source code using git pull.

    Args:
      path (str): path of the dependency.
      repo (str): name of the repository to pull.
      branch (str): which branch to pull

    Returns:
      bool: True if successful or False otherwise.
    """
    logging.info('Resetting %s', repo)

    call = ['git', 'reset', '--hard']
    logging.info(' '.join(call))
    exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
    if exit_code != 0:
      return False

    logging.info('Checking out %s', branch)

    call = ['git', 'checkout', branch]
    logging.info(' '.join(call))
    exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
    if exit_code != 0:
      return False

    logging.info('Pulling %s/%s', repo, branch)

    call = ['git', 'pull']
    logging.info(' '.join(call))
    exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
    if exit_code != 0:
      logging.info('Update %s failed.', repo)
      return False

    logging.info('Update %s successfully.', repo)
    return True

  def _PrepareBuildLibyalDependency(self, name, path):
    """Prepares building a libyal dependency.

    Args:
      name (str): name of the libyal dependency.
      path (str): path of the source of the libyal dependency.

    Returns:
      bool: True if successful or False otherwise.
    """
    logging.info('Preparing build of %s', name)

    if name in ('libewf', 'libvmdk'):
      call = ['powershell.exe', '-File', 'synczlib.ps1']
      logging.info(' '.join(call))
      exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
      if exit_code != 0:
        return False

    if name == 'libewf':
      call = ['powershell.exe', '-File', 'syncwinflexbison.ps1']
      logging.info(' '.join(call))
      exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
      if exit_code != 0:
        return False

    call = ['powershell.exe', '-File', 'synclibs.ps1']
    logging.info(' '.join(call))
    exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
    if exit_code != 0:
      return False

    call = ['powershell.exe', '-File', 'autogen.ps1']
    logging.info(' '.join(call))
    exit_code = subprocess.call(call, stdout=sys.stdout, cwd=path)
    if exit_code != 0:
      return False

    vs2015_path = os.path.join(path, 'vs2015')
    if os.path.exists(vs2015_path):
      shutil.rmtree(vs2015_path)

    msvscpp_convert = os.path.join(
        self._VSTOOLS_PATH, 'scripts', 'msvscpp-convert.py')
    solution_file = os.path.join(path, 'msvscpp', '%s.sln' % name)

    # Enviroment variables need to be of type string with is dependent
    # on the version of Python.
    if sys.version_info[0] < 3:
      environment = {
          'PYTHONPATH'.encode('ascii'): self._VSTOOLS_PATH.encode('ascii')}
    else:
      environment = {'PYTHONPATH': self._VSTOOLS_PATH}

    call = ['python.exe', msvscpp_convert, '--extend-with-x64',
            '--no-python-dll', '--output-format=2015', solution_file]
    logging.info(' '.join(call))

    exit_code = subprocess.call(
        call, stdout=sys.stdout, cwd=path, env=environment)
    if exit_code != 0:
      return False

    return True

  def DownloadAndBuildAllDependencies(self, use_vstools, platform):
    """Downloads and builds dependencies.

    Args:
      use_vstools (bool): use libyal vstools instead of the Sleuthkit provided
          Visual Studio solution and project files.
      platform (str): build platform, such as Win32 or x64.

    Returns:
      bool: True if successful or False otherwise.
    """
    if use_vstools and not os.path.exists(self._VSTOOLS_PATH):
      if not self._GitClone(self._VSTOOLS_REPO_URL, self._VSTOOLS_PATH):
        return False

    for name, environment_variable, default_path in self._LIBYAL_BUILD_TARGETS:
      path = os.getenv(environment_variable, default_path)

      if use_vstools:
        result = self._DownloadAndBuildLibyalDependencyDLLWithVstools(
            name, path, platform)
      else:
        result = self._DownloadAndBuildLibyalDependencyDLL(name, path, platform)

      if not result:
        return False

    return True

  def BuildTSK(self, configuration, platform):
    """Builds the SleuthKit in a specific configurations.

    Args:
      configuration (str): name of the build configuration.
      platform (str): build platform, such as Win32 or x64.

    Returns:
      bool: True if successful or False otherwise.
    """
    # pylint: disable=redefined-argument-from-local
    if configuration:
      configurations = [configuration]
    else:
      configurations = self._TSK_BUILD_CONFIGURATIONS
    if platform:
      platforms = [platform]
    else:
      platforms = self._TSK_BUILD_PLATFORMS

    for configuration in configurations:
      for platform in platforms:
        if not self._BuildTSK(configuration, platform):
          return False

    return True

  def GetMsbuildPath(self):
    """Determines the location of MSBuild.exe.

    Returns:
      str: path of MSBuild.exe.
    """
    # Note that MSBuild in .NET 3.5 does not support vs2010 solution files
    # and MSBuild in .NET 4.0 is needed instead.
    self._msbuild_path = '{0:s}:{1:s}{2:s}'.format(
        'C', os.sep, os.path.join(
            'Windows', 'Microsoft.NET', 'Framework', 'v4.0.30319',
            'MSBuild.exe'))

    if not os.path.exists(self._msbuild_path):
      self._msbuild_path = os.path.normpath(
          'C:\\Program Files (x86)\\MSBuild\\14.0\\Bin\\MSBuild.exe')

    return os.path.exists(self._msbuild_path)


def Main():
  """The main program function.

  Returns:
    bool: True if successful or False if not.
  """
  actions = frozenset(['build', 'prepare'])

  argument_parser = argparse.ArgumentParser(description=(
      'Script to help build the SleuthKit.'))

  argument_parser.add_argument(
      '--branch', action='store', metavar='BRANCH', dest='branch',
      type=str, default='master', help='name of the branch to build.')

  argument_parser.add_argument(
      '--configuration', action='store', metavar='CONFIGURATION',
      dest='configuration', type=str, default='Release',
      help='name of the configuration to build.')

  argument_parser.add_argument(
      '--platform', choices=('Win32', 'x64'), action='store',
      metavar='PLATFORM', dest='platform', default=None,
      help='platform to build either Win32 or x64, default is all.')

  argument_parser.add_argument(
      '--use_vstools', '--use-vstools', dest='use_vstools',
      action='store_true', default=False, help=(
          'use libyal vstools instead of the Sleuthkit provided Visual '
          'Studio solution and project files.'))

  argument_parser.add_argument(
      'action', choices=sorted(actions), action='store',
      metavar='ACTION', default=None, help='action.')

  options = argument_parser.parse_args()

  logging.basicConfig(
      level=logging.INFO, format='[%(levelname)s] %(message)s')

  print('Updating source by %s branch.' % options.branch)

  build_helper = BuildHelper()

  if build_helper.platform not in (
      build_helper.PLATFORM_CYGWIN, build_helper.PLATFORM_WINDOWS):
    print('Currently only Cygwin or Windows supported at this time.')
    return False

  if not build_helper.GetMsbuildPath():
    print('Unable to find MSBuild.exe')
    return False

  if 'APPVEYOR' in os.environ:
    use_vstools = True
  else:
    use_vstools = options.use_vstools

  if options.action in (None, 'prepare'):
    if not build_helper.DownloadAndBuildAllDependencies(
        use_vstools, options.platform):
      return False

  if options.action in (None, 'build'):
    if not build_helper.BuildTSK(options.configuration, options.platform):
      return False

  return True


if __name__ == '__main__':
  if not Main():
    sys.exit(1)
  else:
    sys.exit(0)
