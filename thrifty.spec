Name: thrifty
Version: 0.10
Release: 1%{?dist}
Summary: Utility for archiving or cleaning "rpmdb-out" files
Summary(ru): Утилита для архивирования и очистки от "не-пакетных" файлов
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
Utility for archiving or cleaning "rpmdb-out" files

%description -l ru
Thrifty
Утилита для архивирования и очистки от "не-пакетных" файлов

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

* Sat Mar 03 2012 Fl@sh <kaperang07@gmail.com> - 0.10-1
- Initial build