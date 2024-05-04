# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885749");
  script_version("2024-02-26T05:06:11+0000");
  script_cve_id("CVE-2023-6693");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-26 05:06:11 +0000 (Mon, 26 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-08 19:04:42 +0000 (Mon, 08 Jan 2024)");
  script_tag(name:"creation_date", value:"2024-02-20 02:04:30 +0000 (Tue, 20 Feb 2024)");
  script_name("Fedora: Security Advisory for qemu (FEDORA-2024-c601293124)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c601293124");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OYGUN5HVOXESW7MSNM44E4AE2VNXQB6Y");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the FEDORA-2024-c601293124 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"qemu is an open source virtualizer that provides hardware
emulation for the KVM hypervisor. qemu acts as a virtual
machine monitor together with the KVM kernel modules, and emulates the
hardware for a full system such as a PC and its associated peripherals.");

  script_tag(name:"affected", value:"'qemu' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~8.1.3~3.fc39", rls:"FC39"))) {
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