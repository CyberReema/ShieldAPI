import requests


BASE_URL = "http://127.0.0.1:8000"


findings = []


def add_finding(title, severity, endpoint, description):
    findings.append({
        "title": title,
        "severity": severity,
        "endpoint": endpoint,
        "description": description
    })


def check_broken_access_control():
    endpoint = "/admin/users"
    url = BASE_URL + endpoint

    response = requests.get(url, timeout=5)

    if response.status_code == 200:
        data = response.json()

        if "users" in data:
            add_finding(
                title="Broken Access Control",
                severity="High",
                endpoint=endpoint,
                description="Admin user data is accessible without authentication."
            )


def check_idor_bola():
    endpoint_1 = "/orders/1001"
    endpoint_2 = "/orders/1002"

    response_1 = requests.get(BASE_URL + endpoint_1, timeout=5)
    response_2 = requests.get(BASE_URL + endpoint_2, timeout=5)

    if response_1.status_code == 200 and response_2.status_code == 200:
        data_1 = response_1.json()
        data_2 = response_2.json()

        if "order" in data_1 and "order" in data_2:
            add_finding(
                title="IDOR / BOLA",
                severity="High",
                endpoint="/orders/{order_id}",
                description="Different order records can be accessed by changing the order ID without proving ownership."
            )


def check_sensitive_data_exposure():
    endpoint = "/debug/config"
    url = BASE_URL + endpoint

    response = requests.get(url, timeout=5)

    if response.status_code == 200:
        data = response.json()

        sensitive_keys = [
            "database_url",
            "api_key",
            "jwt_secret"
        ]

        exposed_keys = []

        for key in sensitive_keys:
            if key in data:
                exposed_keys.append(key)

        if exposed_keys:
            add_finding(
                title="Sensitive Data Exposure",
                severity="Critical",
                endpoint=endpoint,
                description=f"Sensitive keys exposed in API response: {', '.join(exposed_keys)}"
            )


def print_report():
    print("\nShieldAPI Security Scanner Report")
    print("=" * 40)

    if not findings:
        print("No vulnerabilities detected.")
        return

    for index, finding in enumerate(findings, start=1):
        print(f"\nFinding {index}")
        print("-" * 40)
        print(f"Title: {finding['title']}")
        print(f"Severity: {finding['severity']}")
        print(f"Endpoint: {finding['endpoint']}")
        print(f"Description: {finding['description']}")

    print("\nScan completed.")


def run_scanner():
    check_broken_access_control()
    check_idor_bola()
    check_sensitive_data_exposure()
    print_report()


if __name__ == "__main__":
    run_scanner()