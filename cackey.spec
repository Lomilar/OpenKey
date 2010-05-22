Summary: PC/SC PKCS#11 Provider for Government Smartcards
Name: cackey
Version: @@VERS@@
Release: 1aceit
License: Public Domain
Packager: Roy Keene <roy.keene@us.army.mil>
URL: https://software.forge.mil/sf/frs/do/listReleases/projects.community_cac/frs.cackey
Source: %{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root


%description
CACKey provides a standard interface (PKCS#11) for smartcards connected to a
PC/SC compliant reader.  It performs a similar function to "CoolKey", but
only supports Government Smartcards.  It supports all Government Smartcards
that implement the Government Smartcard Interoperability Specification (GSC-IS)
v2.1 or newer.


%prep
%setup -q


%build
CFLAGS="%{optflags}" \
	./configure --prefix=%{_prefix} --libdir=%{_libdir} --mandir=%{_mandir}
make  %{?_smp_mflags}


%install
if [ ! %{buildroot} = "/" ]; then %{__rm} -rf %{buildroot}; fi
make DESTDIR=%{buildroot} install


%clean
if [ ! %{buildroot} = "/" ]; then %{__rm} -rf %{buildroot}; fi


%files
%defattr(-,root,root)
%{_libdir}/libcackey.so
%{_libdir}/libcackey_g.so