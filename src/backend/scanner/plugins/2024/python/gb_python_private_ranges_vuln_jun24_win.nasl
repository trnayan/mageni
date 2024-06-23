# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152431");
  script_version("2024-06-19T05:05:42+0000");
  script_tag(name:"last_modification", value:"2024-06-19 05:05:42 +0000 (Wed, 19 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-18 02:41:00 +0000 (Tue, 18 Jun 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2024-4032");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python IP Ranges Vulnerability (Jun 2024) - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to a vulnerability in the ipaddress module.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The 'ipaddress' module contained incorrect information about
  whether certain IPv4 and IPv6 addresses were designated as 'globally reachable' or 'private'.
  This affected the 'is_private' and 'is_global' properties of the ipaddress.IPv4Address,
  ipaddress.IPv4Network, ipaddress.IPv6Address, and ipaddress.IPv6Network classes, where values
  wouldn't be returned in accordance with the latest information from the IANA Special-Purpose
  Address Registries.");

  script_tag(name:"affected", value:"Python prior to version 3.12.4.");

  script_tag(name:"solution", value:"Update to version 3.12.4 or later.");

  script_xref(name:"URL", value:"https://mail.python.org/archives/list/security-announce@python.org/thread/NRUHDUS2IV2USIZM2CVMSFL6SCKU3RZA/");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/113171");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE,
                                          version_regex: "^[0-9]+\.[0-9]+\.[0-9]+"))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.12.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.12.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
