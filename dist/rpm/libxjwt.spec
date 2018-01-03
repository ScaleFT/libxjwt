Name:           libxjwt
Version:        1.0.3
Release:        1%{?dist}

Summary:        Minimal C library for validation of real-world JWTs
License:        Apache 2.0
Group:          System/Libraries
Source0:        https://github.com/ScaleFT/libxjwt/archive/v%{version}.tar.gz

URL:            https://github.com/ScaleFT/libxjwt
Vendor:         ScaleFT http://scaleft.com

BuildRequires:  openssl-devel
BuildRequires:  jansson-devel

Prefix:         %{_prefix}

%description
libxjwt seeks to provide a minimal c89-style library and API surface for validating a compact-form JWT against a set of JWKs. This is not meant to be a general purpose JOSE library. If you are looking for a more general purpose C library, consider cjose.

%files
%{_prefix}/lib/%{name}.*
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
%{_prefix}/include/xjwt/*.h

%prep
rm -Rf $RPM_BUILD_DIR/%{name}-%{version}
tar xvfz $RPM_SOURCE_DIR/v%{version}.tar.gz -C $RPM_BUILD_DIR/

%build
cd %{name}-%{version}
./configure --prefix=%{_prefix}
make

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
cd %{name}-%{version}
make DESTDIR=$RPM_BUILD_ROOT install
