# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885788");
  script_version("2024-02-29T05:05:39+0000");
  script_cve_id("CVE-2024-25580");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-29 05:05:39 +0000 (Thu, 29 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-24 02:04:40 +0000 (Sat, 24 Feb 2024)");
  script_name("Fedora: Security Advisory for mingw-qt5-qtbase (FEDORA-2024-a8cdce27ac)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-a8cdce27ac");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EFUZ35PL77MMSYCRPRK6FFZKKLYQOJVY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-qt5-qtbase'
  package(s) announced via the FEDORA-2024-a8cdce27ac advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This package contains the Qt software toolkit for developing
cross-platform applications.

This is the Windows version of Qt, for use in conjunction with the
Fedora Windows cross-compiler.");

  script_tag(name:"affected", value:"'mingw-qt5-qtbase' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-qt5-qtbase", rpm:"mingw-qt5-qtbase~5.15.12~2.fc39", rls:"FC39"))) {
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