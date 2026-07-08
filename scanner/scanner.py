import argparse
from datetime import datetime
from pathlib import Path

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:8000"

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORTS_DIR = PROJECT_ROOT / "reports"
REPORT_PATH = REPORTS_DIR / "scan-report.md"


class ShieldAPIScanner:
    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")
        self.findings = []
        self.controls = []
        self.session = requests.Session()

    def build_url(self, endpoint):
        return f"{self.base_url}{endpoint}"

    def get(self, endpoint, headers=None):
        try:
            return self.session.get(
                self.build_url(endpoint),
                headers=headers,
                timeout=5
            )
        except requests.RequestException as error:
            self.add_control(
                title="Request failed",
                endpoint=endpoint,
                expected="The API should respond to scanner requests.",
                observed=str(error),
                passed=False,
                details="The backend may not be running."
            )
            return None

    def response_json(self, response):
        try:
            return response.json()
        except ValueError:
            return {}

    def auth_headers(self, token):
        return {
            "Authorization": f"Bearer {token}"
        }

    def add_finding(
        self,
        title,
        severity,
        endpoint,
        owasp_mapping,
        description,
        evidence,
        remediation
    ):
        self.findings.append({
            "title": title,
            "severity": severity,
            "endpoint": endpoint,
            "owasp_mapping": owasp_mapping,
            "description": description,
            "evidence": evidence,
            "remediation": remediation
        })

    def add_control(
        self,
        title,
        endpoint,
        expected,
        observed,
        passed,
        details
    ):
        self.controls.append({
            "title": title,
            "endpoint": endpoint,
            "expected": expected,
            "observed": observed,
            "passed": passed,
            "details": details
        })

    # ------------------------------------------------------------
    # Vulnerability checks
    # ------------------------------------------------------------

    def check_broken_access_control(self):
        endpoint = "/admin/users"
        response = self.get(endpoint)

        if response is None:
            return

        data = self.response_json(response)

        if response.status_code == 200 and "users" in data:
            self.add_finding(
                title="Broken Access Control",
                severity="High",
                endpoint=endpoint,
                owasp_mapping="API5:2023 Broken Function Level Authorization",
                description="Admin user data is accessible without authentication.",
                evidence=f"HTTP {response.status_code} returned a users list without an Authorization header.",
                remediation="Require authentication and verify that the requester has the admin role."
            )

    def check_idor_bola(self):
        endpoint_1 = "/orders/1001"
        endpoint_2 = "/orders/1002"

        response_1 = self.get(endpoint_1)
        response_2 = self.get(endpoint_2)

        if response_1 is None or response_2 is None:
            return

        data_1 = self.response_json(response_1)
        data_2 = self.response_json(response_2)

        order_1 = data_1.get("order", {})
        order_2 = data_2.get("order", {})

        owner_1 = order_1.get("owner")
        owner_2 = order_2.get("owner")

        if (
            response_1.status_code == 200
            and response_2.status_code == 200
            and owner_1
            and owner_2
            and owner_1 != owner_2
        ):
            self.add_finding(
                title="IDOR / BOLA",
                severity="High",
                endpoint="/orders/{order_id}",
                owasp_mapping="API1:2023 Broken Object Level Authorization",
                description="Different users' order records can be accessed by changing the order ID.",
                evidence=f"{endpoint_1} returned owner '{owner_1}' and {endpoint_2} returned owner '{owner_2}' without proving ownership.",
                remediation="Check that the authenticated user owns the requested object or has an authorized admin role."
            )

    def check_sensitive_data_exposure(self):
        endpoint = "/debug/config"
        response = self.get(endpoint)

        if response is None:
            return

        data = self.response_json(response)

        sensitive_keys = [
            "database_url",
            "api_key",
            "jwt_secret"
        ]

        exposed_keys = [
            key for key in sensitive_keys
            if key in data
        ]

        if response.status_code == 200 and exposed_keys:
            self.add_finding(
                title="Sensitive Data Exposure",
                severity="Critical",
                endpoint=endpoint,
                owasp_mapping="API8:2023 Security Misconfiguration",
                description="Sensitive configuration keys are exposed in the API response.",
                evidence=f"Exposed keys: {', '.join(exposed_keys)}",
                remediation="Remove public debug/config endpoints and never return secrets in API responses."
            )

    # ------------------------------------------------------------
    # Secure endpoint validation checks
    # ------------------------------------------------------------

    def validate_secure_admin_endpoint(self):
        endpoint = "/secure/admin/users"

        no_auth_response = self.get(endpoint)
        if no_auth_response is not None:
            self.add_control(
                title="Secure admin endpoint blocks unauthenticated access",
                endpoint=endpoint,
                expected="401 or 403",
                observed=f"HTTP {no_auth_response.status_code}",
                passed=no_auth_response.status_code in [401, 403],
                details="Admin data should not be visible without a token."
            )

        user_response = self.get(
            endpoint,
            headers=self.auth_headers("reema-token-123")
        )
        if user_response is not None:
            self.add_control(
                title="Secure admin endpoint blocks normal users",
                endpoint=endpoint,
                expected="403",
                observed=f"HTTP {user_response.status_code}",
                passed=user_response.status_code == 403,
                details="A normal user should not access admin-only data."
            )

        admin_response = self.get(
            endpoint,
            headers=self.auth_headers("admin-token-123")
        )
        if admin_response is not None:
            self.add_control(
                title="Secure admin endpoint allows admin users",
                endpoint=endpoint,
                expected="200",
                observed=f"HTTP {admin_response.status_code}",
                passed=admin_response.status_code == 200,
                details="An admin token should be allowed to access admin data."
            )

    def validate_secure_order_endpoint(self):
        own_order_endpoint = "/secure/orders/1001"
        other_order_endpoint = "/secure/orders/1002"

        own_order_response = self.get(
            own_order_endpoint,
            headers=self.auth_headers("reema-token-123")
        )
        if own_order_response is not None:
            self.add_control(
                title="Secure order endpoint allows object owner",
                endpoint=own_order_endpoint,
                expected="200",
                observed=f"HTTP {own_order_response.status_code}",
                passed=own_order_response.status_code == 200,
                details="User reema owns order 1001, so access should be allowed."
            )

        other_order_response = self.get(
            other_order_endpoint,
            headers=self.auth_headers("reema-token-123")
        )
        if other_order_response is not None:
            self.add_control(
                title="Secure order endpoint blocks IDOR/BOLA",
                endpoint=other_order_endpoint,
                expected="403",
                observed=f"HTTP {other_order_response.status_code}",
                passed=other_order_response.status_code == 403,
                details="User reema does not own order 1002, so access should be denied."
            )

    def validate_secure_config_endpoint(self):
        endpoint = "/secure/debug/config"

        response = self.get(
            endpoint,
            headers=self.auth_headers("admin-token-123")
        )

        if response is None:
            return

        data = self.response_json(response)

        sensitive_keys = [
            "database_url",
            "api_key",
            "jwt_secret"
        ]

        exposed_keys = [
            key for key in sensitive_keys
            if key in data
        ]

        self.add_control(
            title="Secure config endpoint does not expose secrets",
            endpoint=endpoint,
            expected="No database_url, api_key, or jwt_secret in response",
            observed=f"Exposed keys: {', '.join(exposed_keys) if exposed_keys else 'none'}",
            passed=len(exposed_keys) == 0,
            details="Secure configuration endpoints should return safe metadata only."
        )

    # ------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------

    def severity_counts(self):
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        for finding in self.findings:
            severity = finding["severity"]
            counts[severity] = counts.get(severity, 0) + 1

        return counts

    def print_report(self):
        print("\nShieldAPI Security Scanner Report")
        print("=" * 45)
        print(f"Target: {self.base_url}")
        print(f"Total findings: {len(self.findings)}")
        print(f"Security controls tested: {len(self.controls)}")

        if self.findings:
            print("\nFindings")
            print("-" * 45)

            for index, finding in enumerate(self.findings, start=1):
                print(f"\nFinding {index}: {finding['title']}")
                print(f"Severity: {finding['severity']}")
                print(f"Endpoint: {finding['endpoint']}")
                print(f"OWASP: {finding['owasp_mapping']}")
                print(f"Evidence: {finding['evidence']}")

        if self.controls:
            print("\nSecure Endpoint Validation")
            print("-" * 45)

            for control in self.controls:
                status = "PASS" if control["passed"] else "FAIL"
                print(f"[{status}] {control['title']}")

        print("\nScan completed.")

    def save_markdown_report(self):
        REPORTS_DIR.mkdir(exist_ok=True)

        counts = self.severity_counts()
        passed_controls = len([
            control for control in self.controls
            if control["passed"]
        ])

        report_lines = [
            "# ShieldAPI Security Scanner Report",
            "",
            f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"Target: `{self.base_url}`",
            "",
            "## Executive Summary",
            "",
            f"Total vulnerability findings: **{len(self.findings)}**",
            "",
            f"Secure endpoint controls tested: **{len(self.controls)}**",
            "",
            f"Secure endpoint controls passed: **{passed_controls}/{len(self.controls)}**",
            "",
            "## Severity Summary",
            "",
            "| Severity | Count |",
            "|---|---|",
            f"| Critical | {counts.get('Critical', 0)} |",
            f"| High | {counts.get('High', 0)} |",
            f"| Medium | {counts.get('Medium', 0)} |",
            f"| Low | {counts.get('Low', 0)} |",
            "",
            "## Findings",
            ""
        ]

        if not self.findings:
            report_lines.append("No vulnerabilities detected.")
            report_lines.append("")
        else:
            for index, finding in enumerate(self.findings, start=1):
                report_lines.extend([
                    f"### Finding {index}: {finding['title']}",
                    "",
                    f"**Severity:** {finding['severity']}",
                    "",
                    f"**Endpoint:** `{finding['endpoint']}`",
                    "",
                    f"**OWASP Mapping:** {finding['owasp_mapping']}",
                    "",
                    f"**Description:** {finding['description']}",
                    "",
                    f"**Evidence:** {finding['evidence']}",
                    "",
                    f"**Recommended Remediation:** {finding['remediation']}",
                    ""
                ])

        report_lines.extend([
            "## Secure Endpoint Validation",
            "",
            "| Control | Endpoint | Expected | Observed | Result |",
            "|---|---|---|---|---|"
        ])

        for control in self.controls:
            result = "PASS" if control["passed"] else "FAIL"
            report_lines.append(
                f"| {control['title']} | `{control['endpoint']}` | {control['expected']} | {control['observed']} | {result} |"
            )

        report_lines.extend([
            "",
            "## Methodology",
            "",
            "The scanner sends HTTP requests to intentionally vulnerable endpoints and checks whether sensitive data or unauthorized resources are returned.",
            "",
            "The scanner also sends requests to secure endpoints to validate whether authentication, role-based authorization, object ownership checks, and secret protection are working as expected.",
            "",
            "## Disclaimer",
            "",
            "This project is for educational and defensive cybersecurity learning only. All vulnerabilities are intentionally created inside a local lab environment."
        ])

        REPORT_PATH.write_text(
            "\n".join(report_lines),
            encoding="utf-8"
        )

        print(f"\nMarkdown report saved to: {REPORT_PATH}")

    def run(self):
        self.check_broken_access_control()
        self.check_idor_bola()
        self.check_sensitive_data_exposure()

        self.validate_secure_admin_endpoint()
        self.validate_secure_order_endpoint()
        self.validate_secure_config_endpoint()

        self.print_report()
        self.save_markdown_report()


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ShieldAPI security scanner"
    )

    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help="Base URL of the ShieldAPI backend"
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    scanner = ShieldAPIScanner(args.base_url)
    scanner.run()