Name:		sleuthkit	
Version:	4.6.0
Release:	1%{?dist}
Summary:	The Sleuth Kit (TSK) is a library and collection of command line tools that allow you to investigate volume and file system data.	

Group:		Utilities	
License:	IBM Public License / Common Public License / GPL 2
URL:		http://www.sleuthkit.org	
Packager:	Morgan Weetman <morganweetman[at]users[dot]sourceforge[dot]net>
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	gcc, make

%description
The Sleuth Kit is a collection of UNIX-based command line file and volume system forensic analysis tools. The file system tools allow you to examine file systems of a suspect computer in a non-intrusive fashion. Because the tools do not rely on the operating system to process the file systems, deleted and hidden content is shown.

The volume system (media management) tools allow you to examine the layout of disks and other media. The Sleuth Kit supports DOS partitions, BSD partitions (disk labels), Mac partitions, Sun slices (Volume Table of Contents), and GPT disks. With these tools, you can identify where partitions are located and extract them so that they can be analyzed with file system analysis tools.

%prep
%setup -q


%build
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%dir %{_libdir}
%{_libdir}/*
%dir %{_bindir}
%{_bindir}/*
%dir %{_mandir}/man1
%{_mandir}/man1/*
%dir /usr/include/tsk
/usr/include/tsk/*
%dir /usr/include/tsk/base
/usr/include/tsk/base/*
%dir /usr/include/tsk/fs
/usr/include/tsk/fs/*
%dir /usr/include/tsk/hashdb
/usr/include/tsk/hashdb/*
%dir /usr/include/tsk/img
/usr/include/tsk/img/*
%dir /usr/include/tsk/vs
/usr/include/tsk/vs/*
%dir /usr/include/tsk/auto
/usr/include/tsk/auto/*
%dir /usr/share/tsk
%dir /usr/share/tsk/sorter
/usr/share/tsk/sorter/*
%doc ChangeLog.txt NEWS.txt INSTALL.txt README.txt README_win32.txt



%changelog
* Tue Jun 03 2008 Morgan Weetman <morganweetman[at]users[dot]sourceforge[dot]net>
- (3.0.0-1)      Initial packaging

