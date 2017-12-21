Name:           libxjwt
Version:        1.0.1
Release:        1%{?dist}

Summary:        Minimal C library for validation of real-world JWTs
License:        Apache 2.0
Group:          System/Libraries
Source0:        https://github.com/ScaleFT/libxjwt/archive/v1.0.1.tar.gz

URL:            https://github.com/ScaleFT/libxjwt
Vendor:         ScaleFT http://scaleft.com

BuildRequires:  scons
BuildRequires:  openssl-devel
BuildRequires:  jansson-devel

%description
libxjwt seeks to provide a minimal c89-style library and API surface for validating a compact-form JWT against a set of JWKs. This is not meant to be a general purpose JOSE library. If you are looking for a more general purpose C library, consider cjose.

%files
/usr/local/lib/%{name}.so
/etc/ld.so.conf.d/local.conf
%license $RPM_BUILD_DIR/libxjwt-%{version}/LICENSE
%doc $RPM_BUILD_DIR/libxjwt-%{version}/README.md

%package -n libxjwt-devel
Summary:        libxjwt dev files
Group:          Development/Other
Requires:       %{name} = %{version}-%{release}
Provides:       libxjwt-devel = %{version}-%{release}

%description -n libxjwt-devel
libxjwt development files.

%files -n libxjwt-devel
/usr/local/include/xjwt/*.h

%prep
rm -Rf $RPM_BUILD_DIR/libxjwt-%{version}
tar xvfz $RPM_SOURCE_DIR/v%{version}.tar.gz -C $RPM_BUILD_DIR/

%build
cd libxjwt-%{version}
scons build

%install
cd libxjwt-%{version}
scons install --install-sandbox="$RPM_BUILD_ROOT"
echo /usr/local/lib > $RPM_BUILD_DIR/libxjwt-%{version}/local.conf
install -p -D -m 0644 $RPM_BUILD_DIR/libxjwt-%{version}/local.conf %{buildroot}/etc/ld.so.conf.d/local.conf

%post -p /sbin/ldconfig
