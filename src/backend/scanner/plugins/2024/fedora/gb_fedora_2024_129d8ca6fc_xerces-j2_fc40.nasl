# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886102");
  script_version("2024-03-14T05:06:59+0000");
  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-14 05:06:59 +0000 (Thu, 14 Mar 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 02:18:45 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for xerces-j2 (FEDORA-2024-129d8ca6fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-129d8ca6fc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/A3L535PRBN2PGDAM4OXXCXEVHLH4KYXC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-j2'
  package(s) announced via the FEDORA-2024-129d8ca6fc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Welcome to the future! Xerces2 is the next generation of high performance,
fully compliant XML parsers in the Apache Xerces family. This new version of
Xerces introduces the Xerces Native Interface (XNI), a complete framework for
building parser components and configurations that is extremely modular and
easy to program.

The Apache Xerces2 parser is the reference implementation of XNI but other
parser components, configurations, and parsers can be written using the Xerces
Native Interface. For complete design and implementation documents, refer to
the XNI Manual.

Xerces2 is a fully conforming XML Schema processor. For more information,
refer to the XML Schema page.

Xerces2 also provides a complete implementation of the Document Object Model
Level 3 Core and Load/Save W3C Recommendations and provides a complete
implementation of the XML Inclusions (XInclude) W3C Recommendation. It also
provides support for OASIS XML Catalogs v1.1.

Xerces2 is able to parse documents written according to the XML 1.1
Recommendation, except that it does not yet provide an option to enable
normalization checking as described in section 2.13 of this specification. It
also handles name spaces according to the XML Namespaces 1.1 Recommendation,
and will correctly serialize XML 1.1 documents if the DOM level 3 load/save
APIs are in use.");

  script_tag(name:"affected", value:"'xerces-j2' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.12.2~10.fc40", rls:"FC40"))) {
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