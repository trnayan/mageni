# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886255");
  script_version("2024-04-18T05:05:33+0000");
  script_cve_id("CVE-2024-25081", "CVE-2024-25082");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-04-18 05:05:33 +0000 (Thu, 18 Apr 2024)");
  script_tag(name:"creation_date", value:"2024-03-25 09:37:11 +0000 (Mon, 25 Mar 2024)");
  script_name("Fedora: Security Advisory for fontforge (FEDORA-2024-e01ef71e64)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e01ef71e64");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GCH22HIO2C6M4BZWF5EYIWVFBXL5BQAH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fontforge'
  package(s) announced via the FEDORA-2024-e01ef71e64 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FontForge (former PfaEdit) is a font editor for outline and bitmap
fonts. It supports a range of font formats, including PostScript
(ASCII and binary Type 1, some Type 3 and Type 0), TrueType, OpenType
(Type2) and CID-keyed fonts.");

  script_tag(name:"affected", value:"'fontforge' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"fontforge", rpm:"fontforge~20230101~11.fc40", rls:"FC40"))) {
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