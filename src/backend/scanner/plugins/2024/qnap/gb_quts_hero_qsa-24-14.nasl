# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/o:qnap:quts_hero";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126704");
  script_version("2024-05-01T05:05:35+0000");
  script_tag(name:"last_modification", value:"2024-05-01 05:05:35 +0000 (Wed, 01 May 2024)");
  script_tag(name:"creation_date", value:"2024-04-29 10:41:42 +0000 (Mon, 29 Apr 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");

  script_cve_id("CVE-2023-51364", "CVE-2023-51365");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QuTS hero Multiple Path Traversal Vulnerabilities (QSA-24-14)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/quts_hero/detected");

  script_tag(name:"summary", value:"QNAP QuTS hero is prone to multiple path traversal
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-51364, CVE-2023-51365: QNAP QuTS hero allows to read the contents of unexpected files
  and expose sensitive data via a network.");

  script_tag(name:"affected", value:"QNAP QuTS hero version h4.5.x prior to h4.5.4.2626 and h5.1.x
  prior to h5.1.3.2578.");

  script_tag(name:"solution", value:"Update to version h4.5.4.2626 build 20231225, h5.1.3.2578
  build 20231110 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-24-14");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

build = get_kb_item("qnap/nas/qts/build");

if (version =~ "^4\.5") {
  if (version_is_less(version: version, test_version:"h4.5.4.2626")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h4.5.4.2626", fixed_build: "20231225");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h4.5.4.2626") &&
      (!build || version_is_less(version: build, test_version: "20231225"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h4.5.4.2626", fixed_build: "20231225");
    security_message(port: 0, data: report);
    exit(0);
  }
}

if (version =~ "^5\.1") {
  if (version_is_less(version: version, test_version: "h5.1.3.2578")) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.3.2578", fixed_build: "20231110");
    security_message(port: 0, data: report);
    exit(0);
  }

  if (version_is_equal(version: version, test_version: "h5.1.3.2578") &&
      (!build || version_is_less(version: build, test_version: "20231110"))) {
    report = report_fixed_ver(installed_version: version, installed_build: build,
                              fixed_version: "h5.1.3.2578", fixed_build: "20231110");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);
