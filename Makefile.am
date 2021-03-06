# Copyright (C) 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

AUTOMAKE_OPTIONS = foreign subdir-objects
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = datapath

AM_CPPFLAGS = $(SSL_CFLAGS)
AM_LDFLAGS = $(SSL_LDFLAGS)
AM_LDFLAGS += $(OVS_LDFLAGS)

if WIN32
AM_CPPFLAGS += -I $(top_srcdir)/include/windows
AM_CPPFLAGS += -I $(top_srcdir)/datapath-windows/include
AM_CPPFLAGS += $(PTHREAD_INCLUDES)
AM_CPPFLAGS += $(MSVC_CFLAGS)
AM_LDFLAGS += $(PTHREAD_LDFLAGS)
endif

AM_CPPFLAGS += -I $(top_srcdir)/include
AM_CPPFLAGS += -I $(top_builddir)/include
AM_CPPFLAGS += -I $(top_srcdir)/lib
AM_CPPFLAGS += -I $(top_builddir)/lib

AM_CPPFLAGS += $(SSL_INCLUDES)

AM_CFLAGS = -Wstrict-prototypes
AM_CFLAGS += $(WARNING_FLAGS)
AM_CFLAGS += $(OVS_CFLAGS)

if NDEBUG
AM_CPPFLAGS += -DNDEBUG
AM_CFLAGS += -fomit-frame-pointer
endif

if WIN32
psep=";"
else
psep=":"
endif
# PYTHONDONTWRITEBYTECODE=yes keeps Python from creating .pyc and .pyo
# files.  Creating .py[co] works OK for any given version of Open
# vSwitch, but it causes trouble if you switch from a version with
# foo/__init__.py into an (older) version with plain foo.py, since
# foo/__init__.pyc will cause Python to ignore foo.py.
if INCLUDE_PYTHON_COMPAT
run_python = PYTHONPATH=$(top_srcdir)/python$(psep)$(top_srcdir)/python/compat$(psep)$$PYTHONPATH
else
run_python = PYTHONPATH=$(top_srcdir)/python$(psep)$$PYTHONPATH
endif
run_python += PYTHONDONTWRITEBYTECODE=yes $(PYTHON)


ALL_LOCAL =
BUILT_SOURCES =
CLEANFILES =
CLEAN_LOCAL =
DISTCLEANFILES =
PYCOV_CLEAN_FILES = build-aux/check-structs,cover

# A list of Markdown-formatted documentation that will automatically be
# included in the "make dist-docs" output.
docs = \
	CONTRIBUTING.md \
	CodingStyle.md \
	DESIGN.md \
	FAQ.md \
	INSTALL.md \
	INSTALL.Debian.md \
	INSTALL.Docker.md \
	INSTALL.DPDK.md \
	INSTALL.Fedora.md \
	INSTALL.KVM.md \
	INSTALL.Libvirt.md \
	INSTALL.NetBSD.md \
	INSTALL.RHEL.md \
	INSTALL.SSL.md \
	INSTALL.XenServer.md \
	INSTALL.userspace.md \
	INSTALL.Windows.md \
	IntegrationGuide.md \
	OPENFLOW-1.1+.md \
	PORTING.md \
	README.md \
	README-lisp.md \
	README-native-tunneling.md \
	REPORTING-BUGS.md \
	TODO.md \
	WHY-OVS.md
EXTRA_DIST = \
	$(docs) \
	NOTICE \
	.travis.yml \
	.travis/build.sh \
	.travis/prepare.sh \
	boot.sh \
	build-aux/cccl \
	build-aux/dist-docs \
	build-aux/sodepends.pl \
	build-aux/soexpand.pl \
	$(MAN_FRAGMENTS) \
	$(MAN_ROOTS) \
	Vagrantfile.in
bin_PROGRAMS =
sbin_PROGRAMS =
bin_SCRIPTS =
DIST_HOOKS =
dist_man_MANS =
dist_pkgdata_DATA =
dist_pkgdata_SCRIPTS =
dist_sbin_SCRIPTS =
dist_scripts_SCRIPTS =
dist_scripts_DATA =
INSTALL_DATA_LOCAL =
UNINSTALL_LOCAL =
man_MANS =
MAN_FRAGMENTS =
MAN_ROOTS =
noinst_DATA =
noinst_HEADERS =
lib_LTLIBRARIES =
noinst_man_MANS =
noinst_PROGRAMS =
noinst_SCRIPTS =
OVSIDL_BUILT =
pkgdata_DATA =
sbin_SCRIPTS =
scripts_SCRIPTS =
scripts_DATA =
SUFFIXES =
check_DATA =
pkgconfig_DATA =

scriptsdir = $(pkgdatadir)/scripts
pkgconfigdir = $(libdir)/pkgconfig

# This ensures that files added to EXTRA_DIST are always distributed,
# even if they are inside an Automake if...endif conditional block that is
# disabled by some particular "configure" run.  For more information, see:
# http://article.gmane.org/gmane.comp.sysutils.automake.general/10891
noinst_HEADERS += $(EXTRA_DIST)

ro_c = echo '/* -*- mode: c; buffer-read-only: t -*- */'
ro_shell = printf '\043 Generated automatically -- do not modify!    -*- buffer-read-only: t -*-\n'

SUFFIXES += .in
.in:
	$(AM_V_GEN)$(PERL) $(srcdir)/build-aux/soexpand.pl -I$(srcdir) < $< | \
	    sed \
		-e 's,[@]PKIDIR[@],$(PKIDIR),g' \
                -e 's,[@]LOGDIR[@],$(LOGDIR),g' \
                -e 's,[@]DBDIR[@],$(DBDIR),g' \
                -e 's,[@]PERL[@],$(PERL),g' \
                -e 's,[@]PYTHON[@],$(PYTHON),g' \
                -e 's,[@]RUNDIR[@],$(RUNDIR),g' \
                -e 's,[@]VERSION[@],$(VERSION),g' \
                -e 's,[@]localstatedir[@],$(localstatedir),g' \
                -e 's,[@]pkgdatadir[@],$(pkgdatadir),g' \
                -e 's,[@]sysconfdir[@],$(sysconfdir),g' \
                -e 's,[@]bindir[@],$(bindir),g' \
                -e 's,[@]sbindir[@],$(sbindir),g' \
                -e 's,[@]abs_top_srcdir[@],$(abs_top_srcdir),g' \
            > $@.tmp
	@if head -n 1 $@.tmp | grep '#!' > /dev/null; then \
	    chmod +x $@.tmp; \
	fi
	$(AM_V_at) mv $@.tmp $@

.PHONY: clean-pycov
clean-pycov:
	cd $(srcdir) && rm -f $(PYCOV_CLEAN_FILES)
CLEAN_LOCAL += clean-pycov

# If we're checked out from a Git repository, make sure that every
# file that is in Git is distributed.
#
# We only enable this check when GNU make is in use because the
# Makefile in datapath/linux, needed to get the list of files to
# distribute, requires GNU make extensions.
if GNU_MAKE
ALL_LOCAL += dist-hook-git
dist-hook-git: distfiles
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1; then \
	  (cd datapath && $(MAKE) distfiles);				    \
	  (cat distfiles; sed 's|^|datapath/|' datapath/distfiles) |	    \
	    LC_ALL=C sort -u > all-distfiles;				    \
	  (cd $(srcdir) && git ls-files) | grep -v '\.gitignore$$' |	    \
	    LC_ALL=C sort -u > all-gitfiles;				    \
	  LC_ALL=C comm -1 -3 all-distfiles all-gitfiles > missing-distfiles; \
	  if test -s missing-distfiles; then				    \
	    echo "The distribution is missing the following files:";	    \
	    cat missing-distfiles;					    \
	    exit 1;							    \
	  fi;								    \
	fi
CLEANFILES += all-distfiles all-gitfiles missing-distfiles
# The following is based on commands for the Automake "distdir" target.
distfiles: Makefile
	@srcdirstrip=`echo "$(srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	topsrcdirstrip=`echo "$(top_srcdir)" | sed 's/[].[^$$\\*]/\\\\&/g'`; \
	list='$(DISTFILES)'; \
	for file in $$list; do echo $$file; done | \
	  sed -e "s|^$$srcdirstrip/||;t" \
	      -e "s|^$$topsrcdirstrip/|$(top_builddir)/|;t" | \
          LC_ALL=C sort -u > $@
CLEANFILES += distfiles
endif
.PHONY: dist-hook-git

# Check that every .c file includes <config.h>.
ALL_LOCAL += config-h-check
config-h-check:
	@cd $(srcdir); \
	if test -e .git && (git --version) >/dev/null 2>&1 && \
	   git --no-pager grep -L '#include <config\.h>' `git ls-files | grep '\.c$$' | \
               grep -vE '^datapath|^lib/sflow|^third-party|^datapath-windows'`; \
	then \
	    echo "See above for list of violations of the rule that"; \
	    echo "every C source file must #include <config.h>."; \
	    exit 1; \
	fi
.PHONY: config-h-check

# Check for printf() type modifiers that MSVC doesn't support.
ALL_LOCAL += printf-check
printf-check:
	@cd $(srcdir); \
	if test -e .git && (git --version) >/dev/null 2>&1 && \
	   git --no-pager grep -n -E -e '%[-+ #0-9.*]*([ztj]|hh)' --and --not -e 'ovs_scan' `git ls-files | grep '\.[ch]$$' | \
               grep -vE '^datapath|^lib/sflow|^third-party'`; \
	then \
	    echo "See above for list of violations of the rule that"; \
	    echo "'z', 't', 'j', 'hh' printf() type modifiers are"; \
	    echo "forbidden.  See CodingStyle.md for replacements."; \
	    exit 1; \
	fi
.PHONY: printf-check

# Check that certain data structures are always declared "static".
ALL_LOCAL += static-check
static-check:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	    git --no-pager grep -n -E '^[ 	]+(struct vlog_rate_limit|pthread_once_t|struct ovsthread_once).*=' $(srcdir); \
         then \
	    echo "See above for list of violations of the rule that "; \
	    echo "certain data structures must always be 'static'"; \
	    exit 1; \
	 fi
.PHONY: static-check

# Check that assert.h is not used outside a whitelist of files.
ALL_LOCAL += check-assert-h-usage
check-assert-h-usage:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	    (cd $(srcdir) && git --no-pager grep -l -E '[<]assert.h[>]') | \
	    $(EGREP) -v '^lib/(sflow_receiver|vlog).c$$|^tests/'; \
         then \
	    echo "Files listed above unexpectedly #include <""assert.h"">."; \
	    echo "Please use ovs_assert (from util.h) instead of assert."; \
	    exit 1; \
	 fi
.PHONY: check-assert-h-usage

# Check that LITTLE_ENDIAN and BIG_ENDIAN are not used unless BYTE_ORDER is
# also mentioned.  (<endian.h> always defines the former two constants.  They
# must be compared to BYTE_ORDER to get the machine's correct endianness.  But
# it is better to use WORDS_BIGENDIAN.)
ALL_LOCAL += check-endian
check-endian:
	@if test -e $(srcdir)/.git && (git --version) >/dev/null 2>&1 && \
	    (cd $(srcdir) && git --no-pager grep -l -E \
             -e 'BIG_ENDIAN|LITTLE_ENDIAN' --and --not -e 'BYTE_ORDER' | \
	    $(EGREP) -v '^datapath/'); \
         then \
	    echo "See above for list of files that misuse LITTLE""_ENDIAN"; \
	    echo "or BIG""_ENDIAN.  Please use WORDS_BIGENDIAN instead."; \
	    exit 1; \
	 fi
.PHONY: check-endian

ALL_LOCAL += thread-safety-check
thread-safety-check:
	@cd $(srcdir); \
	if test -e .git && (git --version) >/dev/null 2>&1 && \
	   grep -n -f build-aux/thread-safety-blacklist \
	       `git ls-files | grep '\.[ch]$$' \
                | $(EGREP) -v '^datapath|^lib/sflow|^third-party'` /dev/null \
	       | $(EGREP) -v ':[ 	]*/?\*'; \
	then \
	    echo "See above for list of calls to functions that are"; \
	    echo "blacklisted due to thread safety issues"; \
	    exit 1; \
	fi
EXTRA_DIST += build-aux/thread-safety-blacklist

if HAVE_GROFF
ALL_LOCAL += manpage-check
manpage-check: $(man_MANS) $(dist_man_MANS) $(noinst_man_MANS)
	@error=false; \
	for manpage in $?; do \
		LANG=en_US.UTF-8 groff -w mac -w delim -w escape -w input -w missing -w tab -T utf8 -man -p -z $$manpage >$@.tmp 2>&1; \
		if grep warning: $@.tmp; then error=:; fi; \
		rm -f $@.tmp; \
	done; \
	if $$error; then exit 1; else touch $@; fi
	$(AM_V_GEN) touch -c $@
CLEANFILES += manpage-check
endif

include $(srcdir)/manpages.mk
$(srcdir)/manpages.mk: $(MAN_ROOTS) build-aux/sodepends.pl
	@$(PERL) $(srcdir)/build-aux/sodepends.pl -I. -I$(srcdir) $(MAN_ROOTS) >$(@F).tmp
	@if cmp -s $(@F).tmp $@; then \
		touch $@; \
		rm -f $(@F).tmp; \
	else \
		mv $(@F).tmp $@; \
	fi
CLEANFILES += manpage-dep-check

if VSTUDIO_DDK
ALL_LOCAL += ovsext_make
ovsext_make: datapath-windows/ovsext.sln
	MSBuild.exe datapath-windows/ovsext.sln /target:Build /property:Configuration="$(VSTUDIO_CONFIG)"

CLEAN_LOCAL += ovsext_clean
ovsext_clean: datapath-windows/ovsext.sln
	MSBuild.exe datapath-windows/ovsext.sln /target:Clean /property:Configuration="$(VSTUDIO_CONFIG)"
endif

dist-hook: $(DIST_HOOKS)
all-local: $(ALL_LOCAL)
clean-local: $(CLEAN_LOCAL)
install-data-local: $(INSTALL_DATA_LOCAL)
uninstall-local: $(UNINSTALL_LOCAL)
.PHONY: $(DIST_HOOKS) $(CLEAN_LOCAL) $(INSTALL_DATA_LOCAL) $(UNINSTALL_LOCAL)

modules_install:
if LINUX_ENABLED
	cd datapath/linux && $(MAKE) modules_install
endif

dist-docs:
	VERSION=$(VERSION) $(srcdir)/build-aux/dist-docs $(srcdir) $(docs)
.PHONY: dist-docs

include m4/automake.mk
include lib/automake.mk
include ofproto/automake.mk
include utilities/automake.mk
include tests/automake.mk
include include/automake.mk
include third-party/automake.mk
include debian/automake.mk
include vswitchd/automake.mk
include ovsdb/automake.mk
include rhel/automake.mk
include xenserver/automake.mk
include python/automake.mk
include python/compat/automake.mk
include tutorial/automake.mk
include vtep/automake.mk
include datapath-windows/automake.mk
include datapath-windows/include/automake.mk
