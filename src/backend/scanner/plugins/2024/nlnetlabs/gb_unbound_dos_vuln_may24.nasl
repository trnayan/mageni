# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nlnetlabs:unbound";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152384");
  script_version("2024-06-12T05:05:44+0000");
  script_tag(name:"last_modification", value:"2024-06-12 05:05:44 +0000 (Wed, 12 Jun 2024)");
  script_tag(name:"creation_date", value:"2024-06-11 03:38:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_cve_id("CVE-2024-33655");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Unbound DNS <= 1.19.3 DoS Amplification Vulnerability (DNSBomb)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("unbound_version.nasl");
  script_mandatory_keys("unbound/installed");

  script_tag(name:"summary", value:"Unbound DNS is prone to a denial of service (DoS) amplification
  vulnerability (aka DNSBomb).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The DNSBomb attack, via specially timed DNS queries and
  answers, can cause a Denial of Service on resolvers and spoofed targets.

  Unbound itself is not vulnerable for DoS, rather it can be used to take part in a pulsing DoS
  amplification attack.");

  script_tag(name:"affected", value:"Ubound DNS Resolver version 1.19.3 and prior.");

  script_tag(name:"solution", value:"Update to version 1.20.0 or later.");

  script_xref(name:"URL", value:"https://nlnetlabs.nl/downloads/unbound/CVE-2024-33655.txt");
  script_xref(name:"URL", value:"https://sp2024.ieee-security.org/accepted-papers.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_proto(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
proto = infos["proto"];

if (version_is_less_equal(version: version, test_version: "1.19.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.20.0");
  security_message(port: port, data: report, proto: proto);
  exit(0);
}

exit(99);
