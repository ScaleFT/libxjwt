Name:           libxjwt
Version:        1.0.1
Release:        1%{?dist}

Summary:        Minimal C library for validation of real-world JWTs
License:        Apache 2.0
Group:          System/Libraries
Source0:        https://github.com/ScaleFT/libxjwt/archive/v%{version}.tar.gz

URL:            https://github.com/ScaleFT/libxjwt
Vendor:         ScaleFT http://scaleft.com

BuildRequires:  scons
BuildRequires:  openssl-devel
BuildRequires:  jansson-devel

%description
libxjwt seeks to provide a minimal c89-style library and API surface for validating a compact-form JWT against a set of JWKs. This is not meant to be a general purpose JOSE library. If you are looking for a more general purpose C library, consider cjose.

%files
/usr/lib/%{name}.so
%license $RPM_BUILD_DIR/%{name}-%{version}/LICENSE
%doc $RPM_BUILD_DIR/%{name}-%{version}/README.md

%package -n %{name}-devel
Summary:        %{name} dev files
Group:          Development/Other
Requires:       %{name} = %{version}-%{release}
Provides:       %{name}-devel = %{version}-%{release}

%description -n %{name}-devel
%{name} development files.

%files -n %{name}-devel
/usr/include/xjwt/*.h

%prep
rm -Rf $RPM_BUILD_DIR/%{name}-%{version}
tar xvfz $RPM_SOURCE_DIR/v%{version}.tar.gz -C $RPM_BUILD_DIR/

%build
cd %{name}-%{version}
scons build

%install
cd %{name}-%{version}
scons install --install-sandbox="$RPM_BUILD_ROOT" prefix=/usr

%post -p /sbin/ldconfig
