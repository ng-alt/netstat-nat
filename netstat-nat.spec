Summary 	: netstat-nat displays NAT connections
Name		: netstat-nat
Version		: 1.4.2
Release		: 1
License		: GPL
Packager	: Danny Wijsman <mardan@tweegy.demon.nl>
URL		: http://tweegy.demon.nl/projects/netstat-nat/
Group		: System Environment/firewall
Source		: http://tweegy.demon.nl/download/%{name}-%{version}.tar.gz
BuildRoot	: %{_tmppath}/%{name}-%{version}-root
Prefix		: %{_prefix}

%description
Netstat-nat is a small program written in C. It displays NAT connections,
managed by netfilter/iptables which comes with the > 2.4.x linux kernels.
The program reads its information from '/proc/net/ip_conntrack', which is
the temporary conntrack-storage of netfilter. (http://netfilter.samba.org/)
Netstat-nat takes several arguments (but not needed).

%prep
%setup

%build
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
install -D -s -m 755 %{name} %{buildroot}%{_bindir}/%{name}
install -D -m 444 netstat-nat.1 %{buildroot}%{_mandir}/man1/netstat-nat.1

%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc COPYING README AUTHORS INSTALL CHANGELOG netstat-nat.spec
%{_bindir}/%{name}
%{_mandir}/man*/*

%changelog
* Tue Dec 24 2002 Jose Pedro Oliveira <jpo@di.uminho.pt> 1.4.1-2
- removed a couple of rpmlint warnings

