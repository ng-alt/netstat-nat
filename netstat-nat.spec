%define name netstat-nat
%define version 1.4.1
%define release 1
%define prefix /usr
Summary 	: netstat-nat displays NAT connections
Name		: %{name}
Version		: %{version}
Release		: %{release}
Copyright	: GPL
Packager	: Danny Wijsman <mardan@tweegy.demon.nl>
URL		: http://tweegy.demon.nl/projects/netstat-nat/
Group		: System Environment/firewall
Source		: %{name}-%{version}.tar.gz
BuildRoot	: /tmp/%{name}-%{version}
Prefix		: %{prefix}

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
install -D %{name} %{buildroot}%{_bindir}/%{name}
install -D -m 444 netstat-nat.1 %{buildroot}%{_mandir}/man1/netstat-nat.1

%clean
make clean

%files

%doc COPYING README AUTHORS INSTALL CHANGELOG netstat-nat.spec
%{_bindir}/%{name}
%{_mandir}/man*/*

