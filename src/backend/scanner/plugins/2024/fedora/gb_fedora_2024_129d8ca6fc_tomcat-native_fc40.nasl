# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886219");
  script_version("2024-03-14T05:06:59+0000");
  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-14 05:06:59 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 02:21:10 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for tomcat-native (FEDORA-2024-129d8ca6fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-129d8ca6fc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3ACK6C4SHK52MXEIAKRR2KT2R6K3WZNE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat-native'
  package(s) announced via the FEDORA-2024-129d8ca6fc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tomcat can use the Apache Portable Runtime to provide superior
scalability, performance, and better integration with native server
technologies.  The Apache Portable Runtime is a highly portable library
that is at the heart of Apache HTTP Server 2.x.  APR has many uses,
including access to advanced IO functionality (such as sendfile, epoll
and OpenSSL), OS level functionality (random number generation, system
status, etc), and native process handling (shared memory, NT pipes and
Unix sockets).  This package contains the Tomcat native library which
provides support for using APR in Tomcat.");

  script_tag(name:"affected", value:"'tomcat-native' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"tomcat-native", rpm:"tomcat-native~1.2.36~4.fc40", rls:"FC40"))) {
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