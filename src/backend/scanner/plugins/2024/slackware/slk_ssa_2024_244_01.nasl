# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.13.2024.244.01");
  script_cve_id("CVE-2023-7256", "CVE-2024-8006");
  script_tag(name:"creation_date", value:"2024-09-02 04:09:56 +0000 (Mon, 02 Sep 2024)");
  script_version("2024-09-20T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-09-20 05:05:37 +0000 (Fri, 20 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-19 17:46:03 +0000 (Thu, 19 Sep 2024)");

  script_name("Slackware: Security Advisory (SSA:2024-244-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2024-244-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2024&m=slackware-security.358164");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-7256");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2024-8006");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpcap' package(s) announced via the SSA:2024-244-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New libpcap packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/libpcap-1.10.5-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 Clean up sock_initaddress() and its callers to avoid double frees
 in some cases.
 Fix pcap_findalldevs_ex() not to crash if passed a file:// URL with a
 path to a directory that cannot be opened.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'libpcap' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"libpcap", ver:"1.10.5-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libpcap", ver:"1.10.5-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"libpcap", ver:"1.10.5-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"libpcap", ver:"1.10.5-x86_64-1", rls:"SLKcurrent"))) {
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
