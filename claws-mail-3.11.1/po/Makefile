# Makefile for PO directory in any package using GNU gettext.
# Copyright (C) 1995-1997, 2000-2007, 2009-2010 by Ulrich Drepper <drepper@gnu.ai.mit.edu>
#
# This file can be copied and used freely without restrictions.  It can
# be used in projects which are not available under the GNU General Public
# License but which still want to provide support for the GNU gettext
# functionality.
# Please note that the actual code of GNU gettext is covered by the GNU
# General Public License and is *not* in the public domain.
#
# Origin: gettext-0.18.3
GETTEXT_MACRO_VERSION = 0.18

PACKAGE = claws-mail
VERSION = 3.11.1
PACKAGE_BUGREPORT = 

SED = /bin/sed
SHELL = /bin/sh


srcdir = .
top_srcdir = ..


prefix = /usr/local
exec_prefix = ${prefix}
datarootdir = ${prefix}/share
datadir = ${datarootdir}
localedir = ${datarootdir}/locale
gettextsrcdir = $(datadir)/gettext/po

INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644

# We use $(mkdir_p).
# In automake <= 1.9.x, $(mkdir_p) is defined either as "mkdir -p --" or as
# "$(mkinstalldirs)" or as "$(install_sh) -d". For these automake versions,
# ${SHELL} /home/dell/download/claws/claws-mail-3.11.1/config/install-sh does not start with $(SHELL), so we add it.
# In automake >= 1.10, $(MKDIR_P) is derived from ${MKDIR_P}, which is defined
# either as "/path/to/mkdir -p" or ".../install-sh -c -d". For these automake
# versions, $(mkinstalldirs) and $(install_sh) are unused.
mkinstalldirs = $(SHELL) ${SHELL} /home/dell/download/claws/claws-mail-3.11.1/config/install-sh -d
install_sh = $(SHELL) ${SHELL} /home/dell/download/claws/claws-mail-3.11.1/config/install-sh
MKDIR_P = /bin/mkdir -p
mkdir_p = $(MKDIR_P)

GMSGFMT_ = /usr/bin/msgfmt
GMSGFMT_no = /usr/bin/msgfmt
GMSGFMT_yes = /usr/bin/msgfmt
GMSGFMT = $(GMSGFMT_$(USE_MSGCTXT))
MSGFMT_ = /usr/bin/msgfmt
MSGFMT_no = /usr/bin/msgfmt
MSGFMT_yes = /usr/bin/msgfmt
MSGFMT = $(MSGFMT_$(USE_MSGCTXT))
XGETTEXT_ = /usr/bin/xgettext
XGETTEXT_no = /usr/bin/xgettext
XGETTEXT_yes = /usr/bin/xgettext
XGETTEXT = $(XGETTEXT_$(USE_MSGCTXT))
MSGMERGE = msgmerge
MSGMERGE_UPDATE = /usr/bin/msgmerge --update
MSGINIT = msginit
MSGCONV = msgconv
MSGFILTER = msgfilter

POFILES =  bg.po ca.po cs.po de.po en_GB.po eo.po es.po fi.po fr.po he.po hu.po id_ID.po it.po ja.po lt.po nb.po nl.po pl.po pt_BR.po pt_PT.po ru.po sk.po sv.po uk.po zh_CN.po zh_TW.po
GMOFILES =  bg.gmo ca.gmo cs.gmo de.gmo en_GB.gmo eo.gmo es.gmo fi.gmo fr.gmo he.gmo hu.gmo id_ID.gmo it.gmo ja.gmo lt.gmo nb.gmo nl.gmo pl.gmo pt_BR.gmo pt_PT.gmo ru.gmo sk.gmo sv.gmo uk.gmo zh_CN.gmo zh_TW.gmo
UPDATEPOFILES =  bg.po-update ca.po-update cs.po-update de.po-update en_GB.po-update eo.po-update es.po-update fi.po-update fr.po-update he.po-update hu.po-update id_ID.po-update it.po-update ja.po-update lt.po-update nb.po-update nl.po-update pl.po-update pt_BR.po-update pt_PT.po-update ru.po-update sk.po-update sv.po-update uk.po-update zh_CN.po-update zh_TW.po-update
DUMMYPOFILES =  bg.nop ca.nop cs.nop de.nop en_GB.nop eo.nop es.nop fi.nop fr.nop he.nop hu.nop id_ID.nop it.nop ja.nop lt.nop nb.nop nl.nop pl.nop pt_BR.nop pt_PT.nop ru.nop sk.nop sv.nop uk.nop zh_CN.nop zh_TW.nop
DISTFILES.common = Makefile.in.in remove-potcdate.sin \
$(DISTFILES.common.extra1) $(DISTFILES.common.extra2) $(DISTFILES.common.extra3)
DISTFILES = $(DISTFILES.common) Makevars POTFILES.in \
$(POFILES) $(GMOFILES) \
$(DISTFILES.extra1) $(DISTFILES.extra2) $(DISTFILES.extra3)

POTFILES = \
     ../src/account.c \
     ../src/action.c \
     ../src/addrclip.c \
     ../src/addr_compl.c \
     ../src/addrcustomattr.c \
     ../src/addrduplicates.c \
     ../src/addressadd.c \
     ../src/addressbook.c \
     ../src/addressbook_foldersel.c \
     ../src/addrgather.c \
     ../src/addrindex.c \
     ../src/alertpanel.c \
     ../src/avatars.c \
     ../src/browseldap.c \
     ../src/common/md5.c \
     ../src/common/plugin.c \
     ../src/common/session.c \
     ../src/common/smtp.c \
     ../src/common/socket.c \
     ../src/common/ssl.c \
     ../src/common/ssl_certificate.c \
     ../src/common/string_match.c \
     ../src/common/utils.c \
     ../src/compose.c \
     ../src/crash.c \
     ../src/editaddress.c \
     ../src/editaddress_other_attributes_ldap.c \
     ../src/editbook.c \
     ../src/editgroup.c \
     ../src/editjpilot.c \
     ../src/editldap_basedn.c \
     ../src/editldap.c \
     ../src/edittags.c \
     ../src/editvcard.c \
     ../src/etpan/etpan-ssl.c \
     ../src/etpan/imap-thread.c \
     ../src/etpan/nntp-thread.c \
     ../src/exphtmldlg.c \
     ../src/expldifdlg.c \
     ../src/export.c \
     ../src/exporthtml.c \
     ../src/exportldif.c \
     ../src/file_checker.c \
     ../src/filtering.c \
     ../src/folder.c \
     ../src/foldersel.c \
     ../src/folderview.c \
     ../src/grouplistdialog.c \
     ../src/gtk/about.c \
     ../src/gtk/colorlabel.c \
     ../src/gtk/foldersort.c \
     ../src/gtk/gtkaspell.c \
     ../src/gtk/gtkutils.c \
     ../src/gtk/headers.h \
     ../src/gtk/icon_legend.c \
     ../src/gtk/inputdialog.c \
     ../src/gtk/logwindow.c \
     ../src/gtk/menu.c \
     ../src/gtk/pluginwindow.c \
     ../src/gtk/prefswindow.c \
     ../src/gtk/progressdialog.c \
     ../src/gtk/quicksearch.c \
     ../src/gtk/sslcertwindow.c \
     ../src/headerview.c \
     ../src/image_viewer.c \
     ../src/imap.c \
     ../src/imap_gtk.c \
     ../src/import.c \
     ../src/importldif.c \
     ../src/importmutt.c \
     ../src/importpine.c \
     ../src/inc.c \
     ../src/ldapupdate.c \
     ../src/ldaputil.c \
     ../src/ldif.c \
     ../src/main.c \
     ../src/mainwindow.c \
     ../src/matcher.c \
     ../src/mbox.c \
     ../src/message_search.c \
     ../src/messageview.c \
     ../src/mh.c \
     ../src/mh_gtk.c \
     ../src/mimeview.c \
     ../src/news.c \
     ../src/news_gtk.c \
     ../src/plugins/acpi_notifier/acpi_notifier.c \
     ../src/plugins/address_keeper/address_keeper.c \
     ../src/plugins/address_keeper/address_keeper.h \
     ../src/plugins/address_keeper/address_keeper_prefs.c \
     ../src/plugins/archive/archiver.c \
     ../src/plugins/archive/archiver_gtk.c \
     ../src/plugins/archive/archiver_prefs.c \
     ../src/plugins/att_remover/att_remover.c \
     ../src/plugins/attachwarner/attachwarner.c \
     ../src/plugins/attachwarner/attachwarner_prefs.c \
     ../src/plugins/bogofilter/bogofilter.c \
     ../src/plugins/bogofilter/bogofilter_gtk.c \
     ../src/plugins/bsfilter/bsfilter.c \
     ../src/plugins/bsfilter/bsfilter_gtk.c \
     ../src/plugins/clamd/clamav_plugin.c \
     ../src/plugins/clamd/clamav_plugin_gtk.c \
     ../src/plugins/clamd/libclamd/clamd-plugin.c \
     ../src/plugins/demo/demo.c \
     ../src/plugins/fancy/fancy_prefs.c \
     ../src/plugins/fancy/fancy_viewer.c \
     ../src/plugins/fetchinfo/fetchinfo_plugin.c \
     ../src/plugins/fetchinfo/fetchinfo_plugin_gtk.c \
     ../src/plugins/gdata/cm_gdata_contacts.c \
     ../src/plugins/gdata/cm_gdata_prefs.c \
     ../src/plugins/gdata/gdata_plugin.c \
     ../src/plugins/geolocation/geolocation_plugin.c \
     ../src/plugins/libravatar/libravatar.c \
     ../src/plugins/libravatar/libravatar_prefs.c \
     ../src/plugins/mailmbox/mailmbox_folder.c \
     ../src/plugins/mailmbox/plugin.c \
     ../src/plugins/mailmbox/plugin_gtk.c \
     ../src/plugins/newmail/newmail.c \
     ../src/plugins/notification/notification_banner.c \
     ../src/plugins/notification/notification_foldercheck.c \
     ../src/plugins/notification/notification_lcdproc.c \
     ../src/plugins/notification/notification_plugin.c \
     ../src/plugins/notification/notification_popup.c \
     ../src/plugins/notification/notification_prefs.c \
     ../src/plugins/notification/notification_trayicon.c \
     ../src/plugins/pdf_viewer/poppler_viewer.c \
     ../src/plugins/perl/perl_gtk.c \
     ../src/plugins/pgpcore/autocompletion.c \
     ../src/plugins/pgpcore/passphrase.c \
     ../src/plugins/pgpcore/pgp_viewer.c \
     ../src/plugins/pgpcore/plugin.c \
     ../src/plugins/pgpcore/prefs_gpg.c \
     ../src/plugins/pgpcore/select-keys.c \
     ../src/plugins/pgpcore/sgpgme.c \
     ../src/plugins/pgpinline/pgpinline.c \
     ../src/plugins/pgpinline/plugin.c \
     ../src/plugins/pgpmime/pgpmime.c \
     ../src/plugins/pgpmime/plugin.c \
     ../src/plugins/python/composewindowtype.c \
     ../src/plugins/python/python_plugin.c \
     ../src/plugins/rssyl/old_feeds.c \
     ../src/plugins/rssyl/opml_export.c \
     ../src/plugins/rssyl/opml_import.c \
     ../src/plugins/rssyl/plugin.c \
     ../src/plugins/rssyl/rssyl_add_item.c \
     ../src/plugins/rssyl/rssyl.c \
     ../src/plugins/rssyl/rssyl_cb_menu.c \
     ../src/plugins/rssyl/rssyl_feed.c \
     ../src/plugins/rssyl/rssyl_feed.h \
     ../src/plugins/rssyl/rssyl_feed_props.c \
     ../src/plugins/rssyl/rssyl_gtk.c \
     ../src/plugins/rssyl/rssyl.h \
     ../src/plugins/rssyl/rssyl_prefs.c \
     ../src/plugins/rssyl/rssyl_subscribe.c \
     ../src/plugins/rssyl/rssyl_subscribe_gtk.c \
     ../src/plugins/rssyl/rssyl_update_comments.c \
     ../src/plugins/rssyl/rssyl_update_feed.c \
     ../src/plugins/rssyl/rssyl_update_format.c \
     ../src/plugins/smime/plugin.c \
     ../src/plugins/smime/smime.c \
     ../src/plugins/spam_report/spam_report.c \
     ../src/plugins/spam_report/spam_report_prefs.c \
     ../src/plugins/spamassassin/spamassassin.c \
     ../src/plugins/spamassassin/spamassassin_gtk.c \
     ../src/plugins/tnef_parse/tnef_parse.c \
     ../src/plugins/vcalendar/common-views.c \
     ../src/plugins/vcalendar/day-view.c \
     ../src/plugins/vcalendar/month-view.c \
     ../src/plugins/vcalendar/plugin.c \
     ../src/plugins/vcalendar/vcalendar.c \
     ../src/plugins/vcalendar/vcal_folder.c \
     ../src/plugins/vcalendar/vcal_manager.c \
     ../src/plugins/vcalendar/vcal_meeting_gtk.c \
     ../src/plugins/vcalendar/vcal_prefs.c \
     ../src/pop.c \
     ../src/prefs_account.c \
     ../src/prefs_actions.c \
     ../src/prefs_common.c \
     ../src/prefs_compose_writing.c \
     ../src/prefs_customheader.c \
     ../src/prefs_display_header.c \
     ../src/prefs_ext_prog.c \
     ../src/prefs_filtering_action.c \
     ../src/prefs_filtering.c \
     ../src/prefs_folder_column.c \
     ../src/prefs_folder_item.c \
     ../src/prefs_fonts.c \
     ../src/prefs_gtk.c \
     ../src/prefs_image_viewer.c \
     ../src/prefs_logging.c \
     ../src/prefs_matcher.c \
     ../src/prefs_message.c \
     ../src/prefs_msg_colors.c \
     ../src/prefs_other.c \
     ../src/prefs_quote.c \
     ../src/prefs_receive.c \
     ../src/prefs_send.c \
     ../src/prefs_spelling.c \
     ../src/prefs_summaries.c \
     ../src/prefs_summary_column.c \
     ../src/prefs_summary_open.c \
     ../src/prefs_template.c \
     ../src/prefs_themes.c \
     ../src/prefs_toolbar.c \
     ../src/prefs_wrapping.c \
     ../src/printing.c \
     ../src/privacy.c \
     ../src/procmime.c \
     ../src/procmsg.c \
     ../src/quote_fmt.c \
     ../src/quote_fmt_parse.y \
     ../src/send_message.c \
     ../src/setup.c \
     ../src/sourcewindow.c \
     ../src/ssl_manager.c \
     ../src/summary_search.c \
     ../src/summaryview.c \
     ../src/textview.c \
     ../src/toolbar.c \
     ../src/uri_opener.c \
     ../src/wizard.c

CATALOGS =  bg.gmo ca.gmo cs.gmo de.gmo en_GB.gmo eo.gmo es.gmo fi.gmo fr.gmo he.gmo hu.gmo id_ID.gmo it.gmo ja.gmo lt.gmo nb.gmo nl.gmo pl.gmo pt_BR.gmo pt_PT.gmo ru.gmo sk.gmo sv.gmo uk.gmo zh_CN.gmo zh_TW.gmo

# Makevars gets inserted here. (Don't remove this line!)
# Makefile variables for PO directory in any package using GNU gettext.

# Usually the message domain is the same as the package name.
DOMAIN = $(PACKAGE)

# These two variables depend on the location of this directory.
subdir = po
top_builddir = ..

# These options get passed to xgettext.
XGETTEXT_OPTIONS = \
  --keyword=_ --flag=_:1:pass-c-format \
  --keyword=Q_ --flag=Q_:1:pass-c-format \
  --keyword=N_ --flag=N_:1:pass-c-format \
	--keyword=C_:1c,2 \
  --keyword='proper_name:1,"This is a proper name. See the gettext manual, section Names."' \
  --keyword='proper_name_utf8:1,"This is a proper name. See the gettext manual, section Names."' \
  --flag=error:3:c-format --flag=error_at_line:5:c-format \
  --from-code=UTF-8

# This is the copyright holder that gets inserted into the header of the
# $(DOMAIN).pot file.  Set this to the copyright holder of the surrounding
# package.  (Note that the msgstr strings, extracted from the package's
# sources, belong to the copyright holder of the package.)  Translators are
# expected to transfer the copyright for their translations to this person
# or entity, or to disclaim their copyright.  The empty string stands for
# the public domain; in this case the translators are expected to disclaim
# their copyright.
COPYRIGHT_HOLDER = The Claws Mail Team

# This is the email address or URL to which the translators shall report
# bugs in the untranslated strings:
# - Strings which are not entire sentences, see the maintainer guidelines
#   in the GNU gettext documentation, section 'Preparing Strings'.
# - Strings which use unclear terms or require additional context to be
#   understood.
# - Strings which make invalid assumptions about notation of date, time or
#   money.
# - Pluralisation problems.
# - Incorrect English spelling.
# - Incorrect formatting.
# It can be your email address, or a mailing list address where translators
# can write to without being subscribed, or the URL of a web page through
# which the translators can contact you.
MSGID_BUGS_ADDRESS = paul@claws-mail.org

# This is the list of locale categories, beyond LC_MESSAGES, for which the
# message catalogs shall be used.  It is usually empty.
EXTRA_LOCALE_CATEGORIES =

# This tells whether the $(DOMAIN).pot file contains messages with an 'msgctxt'
# context.  Possible values are "yes" and "no".  Set this to yes if the
# package uses functions taking also a message context, like pgettext(), or
# if in $(XGETTEXT_OPTIONS) you define keywords with a context argument.
USE_MSGCTXT = no

.SUFFIXES:
.SUFFIXES: .po .gmo .mo .sed .sin .nop .po-create .po-update

.po.mo:
	@echo "$(MSGFMT) -c -o $@ $<"; \
	$(MSGFMT) -c -o t-$@ $< && mv t-$@ $@

.po.gmo:
	@lang=`echo $* | sed -e 's,.*/,,'`; \
	test "$(srcdir)" = . && cdcmd="" || cdcmd="cd $(srcdir) && "; \
	echo "$${cdcmd}rm -f $${lang}.gmo && $(GMSGFMT) -c --statistics --verbose -o $${lang}.gmo $${lang}.po"; \
	cd $(srcdir) && rm -f $${lang}.gmo && $(GMSGFMT) -c --statistics --verbose -o t-$${lang}.gmo $${lang}.po && mv t-$${lang}.gmo $${lang}.gmo

.sin.sed:
	sed -e '/^#/d' $< > t-$@
	mv t-$@ $@


all: all-yes

all-yes: stamp-po
all-no:

# Ensure that the gettext macros and this Makefile.in.in are in sync.
CHECK_MACRO_VERSION = \
	test "$(GETTEXT_MACRO_VERSION)" = "0.19" \
	  || { echo "*** error: gettext infrastructure mismatch: using a Makefile.in.in from gettext version $(GETTEXT_MACRO_VERSION) but the autoconf macros are from gettext version 0.19" 1>&2; \
	       exit 1; \
	     }

# $(srcdir)/$(DOMAIN).pot is only created when needed. When xgettext finds no
# internationalized messages, no $(srcdir)/$(DOMAIN).pot is created (because
# we don't want to bother translators with empty POT files). We assume that
# LINGUAS is empty in this case, i.e. $(POFILES) and $(GMOFILES) are empty.
# In this case, stamp-po is a nop (i.e. a phony target).

# stamp-po is a timestamp denoting the last time at which the CATALOGS have
# been loosely updated. Its purpose is that when a developer or translator
# checks out the package via CVS, and the $(DOMAIN).pot file is not in CVS,
# "make" will update the $(DOMAIN).pot and the $(CATALOGS), but subsequent
# invocations of "make" will do nothing. This timestamp would not be necessary
# if updating the $(CATALOGS) would always touch them; however, the rule for
# $(POFILES) has been designed to not touch files that don't need to be
# changed.
stamp-po: $(srcdir)/$(DOMAIN).pot
	test ! -f $(srcdir)/$(DOMAIN).pot || \
	  test -z "$(GMOFILES)" || $(MAKE) $(GMOFILES)
	@test ! -f $(srcdir)/$(DOMAIN).pot || { \
	  echo "touch stamp-po" && \
	  echo timestamp > stamp-poT && \
	  mv stamp-poT stamp-po; \
	}

# Note: Target 'all' must not depend on target '$(DOMAIN).pot-update',
# otherwise packages like GCC can not be built if only parts of the source
# have been downloaded.

# This target rebuilds $(DOMAIN).pot; it is an expensive operation.
# Note that $(DOMAIN).pot is not touched if it doesn't need to be changed.
# The determination of whether the package xyz is a GNU one is based on the
# heuristic whether some file in the top level directory mentions "GNU xyz".
# If GNU 'find' is available, we avoid grepping through monster files.
$(DOMAIN).pot-update: $(POTFILES) $(srcdir)/POTFILES.in remove-potcdate.sed
	if { if (LC_ALL=C find --version) 2>/dev/null | grep GNU >/dev/null; then \
	       LC_ALL=C find -L $(top_srcdir) -maxdepth 1 -type f -size -10000000c -exec grep 'GNU claws-mail' /dev/null '{}' ';' 2>/dev/null; \
	     else \
	       LC_ALL=C grep 'GNU claws-mail' $(top_srcdir)/* 2>/dev/null; \
	     fi; \
	   } | grep -v 'libtool:' >/dev/null; then \
	  package_gnu='GNU '; \
	else \
	  package_gnu=''; \
	fi; \
	if test -n '$(MSGID_BUGS_ADDRESS)' || test '$(PACKAGE_BUGREPORT)' = '@'PACKAGE_BUGREPORT'@'; then \
	  msgid_bugs_address='$(MSGID_BUGS_ADDRESS)'; \
	else \
	  msgid_bugs_address='$(PACKAGE_BUGREPORT)'; \
	fi; \
	case `$(XGETTEXT) --version | sed 1q | sed -e 's,^[^0-9]*,,'` in \
	  '' | 0.[0-9] | 0.[0-9].* | 0.1[0-5] | 0.1[0-5].* | 0.16 | 0.16.[0-1]*) \
	    $(XGETTEXT) --default-domain=$(DOMAIN) --directory=$(top_srcdir) \
	      --add-comments=TRANSLATORS: $(XGETTEXT_OPTIONS)  \
	      --files-from=$(srcdir)/POTFILES.in \
	      --copyright-holder='$(COPYRIGHT_HOLDER)' \
	      --msgid-bugs-address="$$msgid_bugs_address" \
	    ;; \
	  *) \
	    $(XGETTEXT) --default-domain=$(DOMAIN) --directory=$(top_srcdir) \
	      --add-comments=TRANSLATORS: $(XGETTEXT_OPTIONS)  \
	      --files-from=$(srcdir)/POTFILES.in \
	      --copyright-holder='$(COPYRIGHT_HOLDER)' \
	      --package-name="$${package_gnu}claws-mail" \
	      --package-version='3.11.1' \
	      --msgid-bugs-address="$$msgid_bugs_address" \
	    ;; \
	esac
	test ! -f $(DOMAIN).po || { \
	  if test -f $(srcdir)/$(DOMAIN).pot; then \
	    sed -f remove-potcdate.sed < $(srcdir)/$(DOMAIN).pot > $(DOMAIN).1po && \
	    sed -f remove-potcdate.sed < $(DOMAIN).po > $(DOMAIN).2po && \
	    if cmp $(DOMAIN).1po $(DOMAIN).2po >/dev/null 2>&1; then \
	      rm -f $(DOMAIN).1po $(DOMAIN).2po $(DOMAIN).po; \
	    else \
	      rm -f $(DOMAIN).1po $(DOMAIN).2po $(srcdir)/$(DOMAIN).pot && \
	      mv $(DOMAIN).po $(srcdir)/$(DOMAIN).pot; \
	    fi; \
	  else \
	    mv $(DOMAIN).po $(srcdir)/$(DOMAIN).pot; \
	  fi; \
	}

# This rule has no dependencies: we don't need to update $(DOMAIN).pot at
# every "make" invocation, only create it when it is missing.
# Only "make $(DOMAIN).pot-update" or "make dist" will force an update.
$(srcdir)/$(DOMAIN).pot:
	$(MAKE) $(DOMAIN).pot-update

# This target rebuilds a PO file if $(DOMAIN).pot has changed.
# Note that a PO file is not touched if it doesn't need to be changed.
$(POFILES): $(srcdir)/$(DOMAIN).pot
	@lang=`echo $@ | sed -e 's,.*/,,' -e 's/\.po$$//'`; \
	if test -f "$(srcdir)/$${lang}.po"; then \
	  test "$(srcdir)" = . && cdcmd="" || cdcmd="cd $(srcdir) && "; \
	  echo "$${cdcmd}$(MSGMERGE_UPDATE) $(MSGMERGE_OPTIONS) --lang=$${lang} $${lang}.po $(DOMAIN).pot"; \
	  cd $(srcdir) \
	    && { case `$(MSGMERGE_UPDATE) --version | sed 1q | sed -e 's,^[^0-9]*,,'` in \
	           '' | 0.[0-9] | 0.[0-9].* | 0.1[0-7] | 0.1[0-7].*) \
	             $(MSGMERGE_UPDATE) $(MSGMERGE_OPTIONS) $${lang}.po $(DOMAIN).pot;; \
	           *) \
	             $(MSGMERGE_UPDATE) $(MSGMERGE_OPTIONS) --lang=$${lang} $${lang}.po $(DOMAIN).pot;; \
	         esac; \
	       }; \
	else \
	  $(MAKE) $${lang}.po-create; \
	fi


install: install-exec install-data
install-exec:
install-data: install-data-yes
	if test "$(PACKAGE)" = "gettext-tools"; then \
	  $(mkdir_p) $(DESTDIR)$(gettextsrcdir); \
	  for file in $(DISTFILES.common) Makevars.template; do \
	    $(INSTALL_DATA) $(srcdir)/$$file \
			    $(DESTDIR)$(gettextsrcdir)/$$file; \
	  done; \
	  for file in Makevars; do \
	    rm -f $(DESTDIR)$(gettextsrcdir)/$$file; \
	  done; \
	else \
	  : ; \
	fi
install-data-no: all
install-data-yes: all
	@catalogs='$(CATALOGS)'; \
	for cat in $$catalogs; do \
	  cat=`basename $$cat`; \
	  lang=`echo $$cat | sed -e 's/\.gmo$$//'`; \
	  dir=$(localedir)/$$lang/LC_MESSAGES; \
	  $(mkdir_p) $(DESTDIR)$$dir; \
	  if test -r $$cat; then realcat=$$cat; else realcat=$(srcdir)/$$cat; fi; \
	  $(INSTALL_DATA) $$realcat $(DESTDIR)$$dir/$(DOMAIN).mo; \
	  echo "installing $$realcat as $(DESTDIR)$$dir/$(DOMAIN).mo"; \
	  for lc in '' $(EXTRA_LOCALE_CATEGORIES); do \
	    if test -n "$$lc"; then \
	      if (cd $(DESTDIR)$(localedir)/$$lang && LC_ALL=C ls -l -d $$lc 2>/dev/null) | grep ' -> ' >/dev/null; then \
	        link=`cd $(DESTDIR)$(localedir)/$$lang && LC_ALL=C ls -l -d $$lc | sed -e 's/^.* -> //'`; \
	        mv $(DESTDIR)$(localedir)/$$lang/$$lc $(DESTDIR)$(localedir)/$$lang/$$lc.old; \
	        mkdir $(DESTDIR)$(localedir)/$$lang/$$lc; \
	        (cd $(DESTDIR)$(localedir)/$$lang/$$lc.old && \
	         for file in *; do \
	           if test -f $$file; then \
	             ln -s ../$$link/$$file $(DESTDIR)$(localedir)/$$lang/$$lc/$$file; \
	           fi; \
	         done); \
	        rm -f $(DESTDIR)$(localedir)/$$lang/$$lc.old; \
	      else \
	        if test -d $(DESTDIR)$(localedir)/$$lang/$$lc; then \
	          :; \
	        else \
	          rm -f $(DESTDIR)$(localedir)/$$lang/$$lc; \
	          mkdir $(DESTDIR)$(localedir)/$$lang/$$lc; \
	        fi; \
	      fi; \
	      rm -f $(DESTDIR)$(localedir)/$$lang/$$lc/$(DOMAIN).mo; \
	      ln -s ../LC_MESSAGES/$(DOMAIN).mo $(DESTDIR)$(localedir)/$$lang/$$lc/$(DOMAIN).mo 2>/dev/null || \
	      ln $(DESTDIR)$(localedir)/$$lang/LC_MESSAGES/$(DOMAIN).mo $(DESTDIR)$(localedir)/$$lang/$$lc/$(DOMAIN).mo 2>/dev/null || \
	      cp -p $(DESTDIR)$(localedir)/$$lang/LC_MESSAGES/$(DOMAIN).mo $(DESTDIR)$(localedir)/$$lang/$$lc/$(DOMAIN).mo; \
	      echo "installing $$realcat link as $(DESTDIR)$(localedir)/$$lang/$$lc/$(DOMAIN).mo"; \
	    fi; \
	  done; \
	done

install-strip: install

installdirs: installdirs-exec installdirs-data
installdirs-exec:
installdirs-data: installdirs-data-yes
	if test "$(PACKAGE)" = "gettext-tools"; then \
	  $(mkdir_p) $(DESTDIR)$(gettextsrcdir); \
	else \
	  : ; \
	fi
installdirs-data-no:
installdirs-data-yes:
	@catalogs='$(CATALOGS)'; \
	for cat in $$catalogs; do \
	  cat=`basename $$cat`; \
	  lang=`echo $$cat | sed -e 's/\.gmo$$//'`; \
	  dir=$(localedir)/$$lang/LC_MESSAGES; \
	  $(mkdir_p) $(DESTDIR)$$dir; \
	  for lc in '' $(EXTRA_LOCALE_CATEGORIES); do \
	    if test -n "$$lc"; then \
	      if (cd $(DESTDIR)$(localedir)/$$lang && LC_ALL=C ls -l -d $$lc 2>/dev/null) | grep ' -> ' >/dev/null; then \
	        link=`cd $(DESTDIR)$(localedir)/$$lang && LC_ALL=C ls -l -d $$lc | sed -e 's/^.* -> //'`; \
	        mv $(DESTDIR)$(localedir)/$$lang/$$lc $(DESTDIR)$(localedir)/$$lang/$$lc.old; \
	        mkdir $(DESTDIR)$(localedir)/$$lang/$$lc; \
	        (cd $(DESTDIR)$(localedir)/$$lang/$$lc.old && \
	         for file in *; do \
	           if test -f $$file; then \
	             ln -s ../$$link/$$file $(DESTDIR)$(localedir)/$$lang/$$lc/$$file; \
	           fi; \
	         done); \
	        rm -f $(DESTDIR)$(localedir)/$$lang/$$lc.old; \
	      else \
	        if test -d $(DESTDIR)$(localedir)/$$lang/$$lc; then \
	          :; \
	        else \
	          rm -f $(DESTDIR)$(localedir)/$$lang/$$lc; \
	          mkdir $(DESTDIR)$(localedir)/$$lang/$$lc; \
	        fi; \
	      fi; \
	    fi; \
	  done; \
	done

# Define this as empty until I found a useful application.
installcheck:

uninstall: uninstall-exec uninstall-data
uninstall-exec:
uninstall-data: uninstall-data-yes
	if test "$(PACKAGE)" = "gettext-tools"; then \
	  for file in $(DISTFILES.common) Makevars.template; do \
	    rm -f $(DESTDIR)$(gettextsrcdir)/$$file; \
	  done; \
	else \
	  : ; \
	fi
uninstall-data-no:
uninstall-data-yes:
	catalogs='$(CATALOGS)'; \
	for cat in $$catalogs; do \
	  cat=`basename $$cat`; \
	  lang=`echo $$cat | sed -e 's/\.gmo$$//'`; \
	  for lc in LC_MESSAGES $(EXTRA_LOCALE_CATEGORIES); do \
	    rm -f $(DESTDIR)$(localedir)/$$lang/$$lc/$(DOMAIN).mo; \
	  done; \
	done

check: all

info dvi ps pdf html tags TAGS ctags CTAGS ID:

mostlyclean:
	rm -f remove-potcdate.sed
	rm -f stamp-poT
	rm -f core core.* $(DOMAIN).po $(DOMAIN).1po $(DOMAIN).2po *.new.po
	rm -fr *.o

clean: mostlyclean

distclean: clean
	rm -f Makefile Makefile.in POTFILES *.mo

maintainer-clean: distclean
	@echo "This command is intended for maintainers to use;"
	@echo "it deletes files that may require special tools to rebuild."
	rm -f stamp-po $(GMOFILES)

distdir = $(top_builddir)/$(PACKAGE)-$(VERSION)/$(subdir)
dist distdir:
	$(MAKE) update-po
	@$(MAKE) dist2
# This is a separate target because 'update-po' must be executed before.
dist2: stamp-po $(DISTFILES)
	dists="$(DISTFILES)"; \
	if test "$(PACKAGE)" = "gettext-tools"; then \
	  dists="$$dists Makevars.template"; \
	fi; \
	if test -f $(srcdir)/$(DOMAIN).pot; then \
	  dists="$$dists $(DOMAIN).pot stamp-po"; \
	fi; \
	if test -f $(srcdir)/ChangeLog; then \
	  dists="$$dists ChangeLog"; \
	fi; \
	for i in 0 1 2 3 4 5 6 7 8 9; do \
	  if test -f $(srcdir)/ChangeLog.$$i; then \
	    dists="$$dists ChangeLog.$$i"; \
	  fi; \
	done; \
	if test -f $(srcdir)/LINGUAS; then dists="$$dists LINGUAS"; fi; \
	for file in $$dists; do \
	  if test -f $$file; then \
	    cp -p $$file $(distdir) || exit 1; \
	  else \
	    cp -p $(srcdir)/$$file $(distdir) || exit 1; \
	  fi; \
	done

update-po: Makefile
	$(MAKE) $(DOMAIN).pot-update
	test -z "$(UPDATEPOFILES)" || $(MAKE) $(UPDATEPOFILES)
	$(MAKE) update-gmo

# General rule for creating PO files.

.nop.po-create:
	@lang=`echo $@ | sed -e 's/\.po-create$$//'`; \
	echo "File $$lang.po does not exist. If you are a translator, you can create it through 'msginit'." 1>&2; \
	exit 1

# General rule for updating PO files.

.nop.po-update:
	@lang=`echo $@ | sed -e 's/\.po-update$$//'`; \
	if test "$(PACKAGE)" = "gettext-tools"; then PATH=`pwd`/../src:$$PATH; fi; \
	tmpdir=`pwd`; \
	echo "$$lang:"; \
	test "$(srcdir)" = . && cdcmd="" || cdcmd="cd $(srcdir) && "; \
	echo "$${cdcmd}$(MSGMERGE) $(MSGMERGE_OPTIONS) --lang=$$lang $$lang.po $(DOMAIN).pot -o $$lang.new.po"; \
	cd $(srcdir); \
	if { case `$(MSGMERGE) --version | sed 1q | sed -e 's,^[^0-9]*,,'` in \
	       '' | 0.[0-9] | 0.[0-9].* | 0.1[0-7] | 0.1[0-7].*) \
	         $(MSGMERGE) $(MSGMERGE_OPTIONS) -o $$tmpdir/$$lang.new.po $$lang.po $(DOMAIN).pot;; \
	       *) \
	         $(MSGMERGE) $(MSGMERGE_OPTIONS) --lang=$$lang -o $$tmpdir/$$lang.new.po $$lang.po $(DOMAIN).pot;; \
	     esac; \
	   }; then \
	  if cmp $$lang.po $$tmpdir/$$lang.new.po >/dev/null 2>&1; then \
	    rm -f $$tmpdir/$$lang.new.po; \
	  else \
	    if mv -f $$tmpdir/$$lang.new.po $$lang.po; then \
	      :; \
	    else \
	      echo "msgmerge for $$lang.po failed: cannot move $$tmpdir/$$lang.new.po to $$lang.po" 1>&2; \
	      exit 1; \
	    fi; \
	  fi; \
	else \
	  echo "msgmerge for $$lang.po failed!" 1>&2; \
	  rm -f $$tmpdir/$$lang.new.po; \
	fi

$(DUMMYPOFILES):

update-gmo: Makefile $(GMOFILES)
	@:

# Recreate Makefile by invoking config.status. Explicitly invoke the shell,
# because execution permission bits may not work on the current file system.
# Use /bin/bash, which is the shell determined by autoconf for the use by its
# scripts, not $(SHELL) which is hardwired to /bin/sh and may be deficient.
Makefile: Makefile.in.in Makevars $(top_builddir)/config.status POTFILES.in
	cd $(top_builddir) \
	  && /bin/bash ./config.status $(subdir)/$@.in po-directories

force:

# Tell versions [3.59,3.63) of GNU make not to export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
