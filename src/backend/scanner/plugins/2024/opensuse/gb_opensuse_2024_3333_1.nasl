# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856492");
  script_version("2024-10-18T15:39:59+0000");
  script_cve_id("CVE-2024-8250");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-10-18 15:39:59 +0000 (Fri, 18 Oct 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-08-30 16:32:16 +0000 (Fri, 30 Aug 2024)");
  script_tag(name:"creation_date", value:"2024-09-20 04:00:32 +0000 (Fri, 20 Sep 2024)");
  script_name("openSUSE: Security Advisory for wireshark (SUSE-SU-2024:3333-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3333-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/PKIPUVYPW5ZK2TC2AJY43BLJZ36FIXSK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark'
  package(s) announced via the SUSE-SU-2024:3333-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for wireshark fixes the following issues:

  * Upgraded Wireshark to version 3.6.24.

  * CVE-2024-8250: Fixed NTLMSSP dissector crash (bsc#1229907).");

  script_tag(name:"affected", value:"'wireshark' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libwsutil13", rpm:"libwsutil13~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt", rpm:"wireshark-ui-qt~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debuginfo", rpm:"wireshark-debuginfo~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwsutil13-debuginfo", rpm:"libwsutil13-debuginfo~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark15-debuginfo", rpm:"libwireshark15-debuginfo~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap12", rpm:"libwiretap12~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-debugsource", rpm:"wireshark-debugsource~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwireshark15", rpm:"libwireshark15~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwiretap12-debuginfo", rpm:"libwiretap12-debuginfo~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-devel", rpm:"wireshark-devel~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-ui-qt-debuginfo", rpm:"wireshark-ui-qt-debuginfo~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~3.6.24~150000.3.118.1", rls:"openSUSELeap15.5"))) {
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