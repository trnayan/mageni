# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885915");
  script_version("2024-03-14T05:06:59+0000");
  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-14 05:06:59 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 02:14:56 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for snakeyaml (FEDORA-2024-129d8ca6fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-129d8ca6fc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Z2BNITUJG32JJ2YVNPWQAVL65J5ZHRZU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'snakeyaml'
  package(s) announced via the FEDORA-2024-129d8ca6fc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SnakeYAML features:

  * a complete YAML 1.1 parser. In particular,
      SnakeYAML can parse all examples from the specification.

  * Unicode support including UTF-8/UTF-16 input/output.

  * high-level API for serializing and deserializing
      native Java objects.

  * support for all types from the YAML types repository.

  * relatively sensible error messages.");

  script_tag(name:"affected", value:"'snakeyaml' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"snakeyaml", rpm:"snakeyaml~1.33~3.fc40", rls:"FC40"))) {
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