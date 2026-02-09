BIN_TARGETS := \
smtpd-starttls-proxy-io \
qmail-remote \
qmail-remote-io

LIBEXEC_TARGETS :=

EXTRA_INSTALL += install-qmailr

QMAILR_UID := $(firstword $(subst :, ,$(QMAILR_IDS)))
QMAILR_GID := $(lastword $(subst :, ,$(QMAILR_IDS)))

install-qmailr:
	mkdir -p -- $(DESTDIR)$(QMAIL_HOME)/run/qmail-remote
	chgrp -- $(QMAILR_GID) $(DESTDIR)$(QMAIL_HOME)/run
	chmod 02750 $(DESTDIR)$(QMAIL_HOME)/run
	chown -- $(QMAILR_IDS) $(DESTDIR)$(QMAIL_HOME)/run/qmail-remote
	chmod 02700 $(DESTDIR)$(QMAIL_HOME)/run/qmail-remote
	chown -- $(QMAILR_IDS) $(DESTDIR)$(QMAIL_HOME)/run/qmail-remote
	chmod 02750 $(DESTDIR)$(QMAIL_HOME)/run/qmail-remote
	touch -- $(DESTDIR)$(QMAIL_HOME)/run/qmail-remote/tcpto6
	chown -- $(QMAILR_IDS) $(DESTDIR)$(QMAIL_HOME)/run/qmail-remote/tcpto6
	chmod 0640 $(DESTDIR)$(QMAIL_HOME)/run/qmail-remote/tcpto6
