# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886205");
  script_version("2024-03-14T05:06:59+0000");
  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-14 05:06:59 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 02:20:54 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for bouncycastle (FEDORA-2024-129d8ca6fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-129d8ca6fc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VE65AAJAFC2KE2KWNPTVNT45PQ3FHLJL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bouncycastle'
  package(s) announced via the FEDORA-2024-129d8ca6fc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Bouncy Castle Crypto package is a Java implementation of cryptographic
algorithms. This jar contains JCE provider and lightweight API for the
Bouncy Castle Cryptography APIs for JDK 1.5 to JDK 1.8.");

  script_tag(name:"affected", value:"'bouncycastle' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"bouncycastle", rpm:"bouncycastle~1.70~13.fc40", rls:"FC40"))) {
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