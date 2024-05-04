# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886105");
  script_version("2024-03-14T05:06:59+0000");
  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-14 05:06:59 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 02:18:49 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for scannotation (FEDORA-2024-129d8ca6fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-129d8ca6fc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ZWRBUM2EVQWDCCJTPMZVOIUQNCWNAVN3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'scannotation'
  package(s) announced via the FEDORA-2024-129d8ca6fc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Scannotation is a Java library that creates an annotation database
from a set of .class files.This database is really just a set of maps that index
what annotations are used and what classes are using them. Why do you need this?
What if you are an annotation framework like an EJB 3.0 container and you want
to automatically scan your classpath for EJB annotations so that you know what
to deploy? Scannotation gives you apis that allow you to find archives in your
classpath or WAR (web application) that you want to scan, then automatically
scans them without loading each and every class within those archives");

  script_tag(name:"affected", value:"'scannotation' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"scannotation", rpm:"scannotation~1.0.3~0.33.r12.fc40", rls:"FC40"))) {
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