# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.887238");
  script_version("2024-06-21T05:05:42+0000");
  script_cve_id("CVE-2024-34055");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-06-21 05:05:42 +0000 (Fri, 21 Jun 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-06-11 17:16:29 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-15 04:08:00 +0000 (Sat, 15 Jun 2024)");
  script_name("Fedora: Security Advisory for cyrus-imapd (FEDORA-2024-f3e0255c75)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-f3e0255c75");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CJZQAE3XC2GBCE5KSTWJ5A6QYANFWGFB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-imapd'
  package(s) announced via the FEDORA-2024-f3e0255c75 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Cyrus IMAP (Internet Message Access Protocol) server provides access to
personal mail, system-wide bulletin boards, news-feeds, calendar and contacts
through the IMAP, JMAP, NNTP, CalDAV and CardDAV protocols. The Cyrus IMAP
server is a scalable enterprise groupware system designed for use from small to
large enterprise environments using technologies based on well-established Open
Standards.

A full Cyrus IMAP implementation allows a seamless mail and bulletin board
environment to be set up across one or more nodes. It differs from other IMAP
server implementations in that it is run on sealed nodes, where users are not
normally permitted to log in. The mailbox database is stored in parts of the
filesystem that are private to the Cyrus IMAP system. All user access to mail
is through software using the IMAP, IMAPS, JMAP, POP3, POP3S, KPOP, CalDAV
and/or CardDAV protocols.

The private mailbox database design gives the Cyrus IMAP server large
advantages in efficiency, scalability, and administratability. Multiple
concurrent read/write connections to the same mailbox are permitted. The server
supports access control lists on mailboxes and storage quotas on mailbox
hierarchies.");

  script_tag(name:"affected", value:"'cyrus-imapd' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~3.8.3~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);