# main.py
# Entry point for the Kubernetes Security Auditor.
# Runs all checks and generates HTML and JSON reports.

import json
import os
from datetime import datetime, timezone

# Toggle between mock and real Kubernetes data
USE_MOCK_DATA = True

if USE_MOCK_DATA:
    from auditor.mock_data import get_mock_pods as get_pods
    from auditor.mock_data import get_mock_rbac as get_rbac
    from auditor.mock_data import get_mock_secrets as get_secrets
    from auditor.mock_data import get_mock_namespaces as get_namespaces
else:
    from auditor.k8s_data import get_k8s_pods as get_pods
    from auditor.k8s_data import get_k8s_rbac as get_rbac
    from auditor.k8s_data import get_k8s_secrets as get_secrets
    from auditor.k8s_data import get_k8s_namespaces as get_namespaces

from auditor.checks import check_pods, check_rbac, check_secrets, check_namespaces
from auditor.report import generate_html_report

def run_audit():
    print("\n" + "=" * 55)
    print("  KUBERNETES SECURITY AUDITOR")
    print("=" * 55 + "\n")

    # Step 1 — Get data
    try:
        print("[1] Fetching cluster data...")
        pods = get_pods()
        rbac = get_rbac()
        secrets = get_secrets()
        namespaces = get_namespaces()
        print(f"  Found {len(pods)} pods, {len(rbac)} RBAC bindings, {len(secrets)} secrets, {len(namespaces)} namespaces\n")
    except Exception as e:
        print(f"  [FATAL] Failed to fetch cluster data: {e}")
        return

    # Step 2 — Run checks
    print("[2] Running security checks...")
    try:
        pod_profiles = check_pods(pods)
        rbac_profiles = check_rbac(rbac)
        secret_profiles = check_secrets(secrets)
        namespace_profiles = check_namespaces(namespaces)
        all_profiles = pod_profiles + rbac_profiles + secret_profiles + namespace_profiles
        all_profiles.sort(key=lambda p: p.total_risk_score(), reverse=True)
        print(f"  Found {sum(len(p.findings) for p in all_profiles)} findings across {len(all_profiles)} resources\n")
    except Exception as e:
        print(f"  [ERROR] Check failed: {e}")
        return

    # Step 3 — Print results
    print("[3] Audit Results\n")
    for profile in all_profiles:
        print(f"  [{profile.highest_severity()}] {profile.resource_name} ({profile.resource_type}) — Risk Score: {profile.total_risk_score()}")
        for finding in profile.findings:
            print(f"    - {finding.issue}")
            print(f"      Recommendation: {finding.recommendation}")
        print()

    # Step 4 — Save JSON report
    try:
        os.makedirs("output", exist_ok=True)
        findings_dict = {
            "audit_timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "total_findings": sum(len(p.findings) for p in all_profiles),
            "resources": [p.to_dict() for p in all_profiles]
        }
        json_path = os.path.join("output", "k8s_audit_report.json")
        with open(json_path, "w") as f:
            json.dump(findings_dict, f, indent=4, default=str)
        print(f"[4] JSON report saved to {json_path}")
    except Exception as e:
        print(f"  [ERROR] Failed to save JSON: {e}")

    # Step 5 — Save HTML report
    try:
        html_path = os.path.join("output", "k8s_audit_report.html")
        generate_html_report(all_profiles, html_path)
        os.startfile(html_path)
    except Exception as e:
        print(f"  [ERROR] Failed to generate HTML report: {e}")

    print("\nDone.")

run_audit()