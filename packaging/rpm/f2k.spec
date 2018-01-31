Name:    f2k
Version: %{__version}
Release: %{__release}%{?dist}

License: GNU AGPLv3
URL: https://github.com/redBorder/f2k
Source0: %{name}-%{version}.tar.gz

BuildRequires: gcc git make librd-devel librdkafka-devel GeoIP-devel libpcap-devel 
BuildRequires: udns-devel libzookeeper-devel rb_macs_vendors jansson-devel python34

Summary: Netflow to Json/Kafka collector
Group:   Development/Libraries/C and C++
Requires: librd0 librdkafka1 libpcap libzookeeper rb_macs_vendors jansson

%description
%{summary}

%prep
%setup -qn %{name}-%{version}

%build
./configure --prefix=/usr
make
make manuf

%install
DESTDIR=%{buildroot} make install
mkdir -p %{buildroot}/etc/f2k
mkdir -p %{buildroot}/var/lib/f2k
install -D -m 644 f2k.service %{buildroot}/usr/lib/systemd/system/f2k.service
install -D -m 644 manuf %{buildroot}/var/lib/f2k/mac_vendors

%clean
rm -rf %{buildroot}

%pre
getent group f2k >/dev/null || groupadd -r f2k
getent passwd f2k >/dev/null || \
    useradd -r -g f2k -d / -s /sbin/nologin \
    -c "User of f2k service" f2k
exit 0

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%files
%defattr(755,root,root)
/usr/bin/f2k
%defattr(755,root,root)
/etc/f2k
%defattr(644,root,root)
/usr/lib/systemd/system/f2k.service
%defattr(755,f2k,f2k)
/var/lib/f2k

%changelog
* Tue Jan 10 2017 Alberto Rodríguez <arodriguez@redborder.com> - 1.0.1-1
- first spec version
