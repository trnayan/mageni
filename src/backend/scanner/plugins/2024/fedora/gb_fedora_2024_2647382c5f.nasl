# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885556");
  script_cve_id("CVE-2023-32650", "CVE-2023-34087", "CVE-2023-34436", "CVE-2023-35004", "CVE-2023-35057", "CVE-2023-35128", "CVE-2023-35702", "CVE-2023-35703", "CVE-2023-35704", "CVE-2023-35955", "CVE-2023-35956", "CVE-2023-35957", "CVE-2023-35958", "CVE-2023-35959", "CVE-2023-35960", "CVE-2023-35961", "CVE-2023-35962", "CVE-2023-35963", "CVE-2023-35964", "CVE-2023-35969", "CVE-2023-35970", "CVE-2023-35989", "CVE-2023-35992", "CVE-2023-35994", "CVE-2023-35995", "CVE-2023-35996", "CVE-2023-35997", "CVE-2023-36746", "CVE-2023-36747", "CVE-2023-36861", "CVE-2023-36864", "CVE-2023-36915", "CVE-2023-36916", "CVE-2023-37282", "CVE-2023-37416", "CVE-2023-37417", "CVE-2023-37418", "CVE-2023-37419", "CVE-2023-37420", "CVE-2023-37442", "CVE-2023-37443", "CVE-2023-37444", "CVE-2023-37445", "CVE-2023-37446", "CVE-2023-37447", "CVE-2023-37573", "CVE-2023-37574", "CVE-2023-37575", "CVE-2023-37576", "CVE-2023-37577", "CVE-2023-37578", "CVE-2023-37921", "CVE-2023-37922", "CVE-2023-37923", "CVE-2023-38583", "CVE-2023-38618", "CVE-2023-38619", "CVE-2023-38620", "CVE-2023-38621", "CVE-2023-38622", "CVE-2023-38623", "CVE-2023-38648", "CVE-2023-38649", "CVE-2023-38650", "CVE-2023-38651", "CVE-2023-38652", "CVE-2023-38653", "CVE-2023-38657", "CVE-2023-39234", "CVE-2023-39235", "CVE-2023-39270", "CVE-2023-39271", "CVE-2023-39272", "CVE-2023-39273", "CVE-2023-39274", "CVE-2023-39275", "CVE-2023-39316", "CVE-2023-39317", "CVE-2023-39413", "CVE-2023-39414", "CVE-2023-39443", "CVE-2023-39444");
  script_tag(name:"creation_date", value:"2024-01-18 09:14:15 +0000 (Thu, 18 Jan 2024)");
  script_version("2024-09-13T15:40:36+0000");
  script_tag(name:"last_modification", value:"2024-09-13 15:40:36 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 15:15:25 +0000 (Mon, 08 Jan 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-2647382c5f)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-2647382c5f");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-2647382c5f");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257435");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2257437");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtkwave' package(s) announced via the FEDORA-2024-2647382c5f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Cumulative bug-fix update.

This update includes fixes for multiple security issues found by Talos in which specially crafted input files could lead to arbitrary code execution. A victim would need to open a malicious file to trigger these vulnerabilities.");

  script_tag(name:"affected", value:"'gtkwave' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"gtkwave", rpm:"gtkwave~3.3.118~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtkwave-debuginfo", rpm:"gtkwave-debuginfo~3.3.118~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtkwave-debugsource", rpm:"gtkwave-debugsource~3.3.118~1.fc39", rls:"FC39"))) {
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
