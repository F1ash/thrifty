Name: thrifty
Version: 0.27
Release: 1%{?dist}
Summary: Utility for archiving or cleaning "rpmdb-out" files
Summary(ru): Утилита для архивирования и очистки "не-пакетных" файлов
Group: Applications/System
License: GPL2+
Source0: %{name}-%{version}.tar.bz2
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
URL: https://github.com/F1ash/thrifty
BuildArch: noarch

Requires: python
BuildRequires: desktop-file-utils

%description
Thrifty
Utility for archiving or cleaning "rpmdb-out" files and
verifying brocken "rpmdb" files in specified catalogs

%description -l ru
Thrifty
Утилита для архивирования или очистки "не-пакетных" файлов
и проверки повреждённых "пакетных" файлов в заданных каталогах.

%prep
%setup -q

%build

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_datadir}/%{name}
install -D -m 755 -p %{name} $RPM_BUILD_ROOT/%{_bindir}/%{name}
install -D -m 755 -p %{name}.py $RPM_BUILD_ROOT/%{_datadir}/%{name}/
install -D -m 644 -p Functions.py $RPM_BUILD_ROOT/%{_datadir}/%{name}/

%files
%defattr(-,root,root)
%{_bindir}/%{name}
%dir %{_datadir}/%{name}
%{_datadir}/%{name}/*

%clean
rm -rf $RPM_BUILD_ROOT

%changelog

* Sat Mar 19 2012 Fl@sh <kaperang07@gmail.com> - 0.27-1
- version updated

* Sat Mar 15 2012 Fl@sh <kaperang07@gmail.com> - 0.25-1
- version updated

* Sat Mar 13 2012 Fl@sh <kaperang07@gmail.com> - 0.20-1
- version updated

* Sat Mar 03 2012 Fl@sh <kaperang07@gmail.com> - 0.10-1
- Initial build
