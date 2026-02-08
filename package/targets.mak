BIN_TARGETS := \
smtpd-starttls-proxy-io \
qmail-remote \
qmail-remote-io

LIBEXEC_TARGETS :=

EXTRA_INSTALL += install-qmailr

QMAILR_UID := $(firstword $(subst :, ,$(QMAILR_IDS)))
QMAILR_GID := $(lastword $(subst :, ,$(QMAILR_IDS)))

install-qmailr:
	mkdir -p -- $(QMAIL_HOME)/run/qmail-remote
	chgrp -- $(QMAILR_GID) $(QMAIL_HOME)/run
	chmod 02750 $(QMAIL_HOME)/run
	chown -- $(QMAILR_IDS) $(QMAIL_HOME)/run/qmail-remote
	chmod 02700 $(QMAIL_HOME)/run/qmail-remote
	chown -- $(QMAILR_IDS) $(QMAIL_HOME)/run/qmail-remote
	chmod 02750 $(QMAIL_HOME)/run/qmail-remote
	touch -- $(QMAIL_HOME)/run/qmail-remote/tcpto6
	chown -- $(QMAILR_IDS) $(QMAIL_HOME)/run/qmail-remote/tcpto6
	chmod 0640 $(QMAIL_HOME)/run/qmail-remote/tcpto6
