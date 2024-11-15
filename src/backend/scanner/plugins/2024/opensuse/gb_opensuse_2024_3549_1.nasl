# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856542");
  script_version("2024-10-16T05:05:34+0000");
  script_cve_id("CVE-2024-31227", "CVE-2024-31228", "CVE-2024-31449");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-10-16 05:05:34 +0000 (Wed, 16 Oct 2024)");
  script_tag(name:"creation_date", value:"2024-10-09 04:00:45 +0000 (Wed, 09 Oct 2024)");
  script_name("openSUSE: Security Advisory for redis7 (SUSE-SU-2024:3549-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:3549-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ERBNKO5R6HN6V2MTKU2ALVBKHGBXJ7YL");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'redis7'
  package(s) announced via the SUSE-SU-2024:3549-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for redis7 fixes the following issues:

  * CVE-2024-31227: Fixed parsing issue leading to denail of service
      (bsc#1231266)

  * CVE-2024-31228: Fixed unbounded recursive pattern matching (bsc#1231265)

  * CVE-2024-31449: Fixed integer overflow bug in Lua bit_tohex (bsc#1231264)");

  script_tag(name:"affected", value:"'redis7' package(s) on openSUSE Leap 15.5.");

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

  if(!isnull(res = isrpmvuln(pkg:"redis7", rpm:"redis7~7.0.8~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis7-debugsource", rpm:"redis7-debugsource~7.0.8~150500.3.12.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"redis7-debuginfo", rpm:"redis7-debuginfo~7.0.8~150500.3.12.1", rls:"openSUSELeap15.5"))) {
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