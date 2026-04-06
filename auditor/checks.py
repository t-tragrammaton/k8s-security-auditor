# checks.py
# Kubernetes security checks using dataclasses and risk scoring.
# Covers pods, RBAC, secrets, network policies, and namespaces.

from dataclasses import dataclass, field
from typing import List

# -----------------------------------------------
# DATACLASSES
# -----------------------------------------------

@dataclass
class Finding:
    resource_id: str
    resource_name: str
    resource_type: str
    issue: str
    severity: str
    risk_score: int
    recommendation: str

@dataclass
class RiskProfile:
    resource_id: str
    resource_name: str
    resource_type: str
    findings: List[Finding] = field(default_factory=list)

    def total_risk_score(self):
        return sum(f.risk_score for f in self.findings)

    def highest_severity(self):
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: order.get(f.severity, 0)).severity

    def to_dict(self):
        return {
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "total_risk_score": self.total_risk_score(),
            "highest_severity": self.highest_severity(),
            "findings": [
                {
                    "issue": f.issue,
                    "severity": f.severity,
                    "risk_score": f.risk_score,
                    "recommendation": f.recommendation
                }
                for f in self.findings
            ]
        }


# -----------------------------------------------
# CHECKS
# -----------------------------------------------

def check_pods(pods) -> List[RiskProfile]:
    profiles = []

    for pod in pods:
        profile = RiskProfile(
            resource_id=f"{pod['namespace']}/{pod['name']}",
            resource_name=pod["name"],
            resource_type="Pod"
        )

        try:
            # Host network access
            if pod.get("hostNetwork"):
                profile.findings.append(Finding(
                    resource_id=profile.resource_id,
                    resource_name=pod["name"],
                    resource_type="Pod",
                    issue="Pod has hostNetwork access — shares host network namespace",
                    severity="CRITICAL",
                    risk_score=95,
                    recommendation="Remove hostNetwork: true unless absolutely required. Use a NetworkPolicy instead"
                ))

            # Host PID access
            if pod.get("hostPID"):
                profile.findings.append(Finding(
                    resource_id=profile.resource_id,
                    resource_name=pod["name"],
                    resource_type="Pod",
                    issue="Pod has hostPID access — can see all host processes",
                    severity="CRITICAL",
                    risk_score=95,
                    recommendation="Remove hostPID: true — this allows container escape via process manipulation"
                ))

            # Default service account
            if pod.get("serviceAccountName") == "default":
                profile.findings.append(Finding(
                    resource_id=profile.resource_id,
                    resource_name=pod["name"],
                    resource_type="Pod",
                    issue="Pod uses default service account",
                    severity="MEDIUM",
                    risk_score=50,
                    recommendation="Create a dedicated service account per workload with minimal RBAC permissions"
                ))

            # Container-level checks
            for container in pod.get("containers", []):
                ctx = container.get("securityContext", {})
                name = container["name"]

                # Running as root
                if ctx.get("runAsRoot"):
                    profile.findings.append(Finding(
                        resource_id=profile.resource_id,
                        resource_name=f"{pod['name']}/{name}",
                        resource_type="Container",
                        issue="Container runs as root",
                        severity="HIGH",
                        risk_score=80,
                        recommendation="Set runAsNonRoot: true and specify a non-zero runAsUser in securityContext"
                    ))

                # Privileged container
                if ctx.get("privileged"):
                    profile.findings.append(Finding(
                        resource_id=profile.resource_id,
                        resource_name=f"{pod['name']}/{name}",
                        resource_type="Container",
                        issue="Container is running in privileged mode",
                        severity="CRITICAL",
                        risk_score=100,
                        recommendation="Remove privileged: true — privileged containers can escape to the host"
                    ))

                # Privilege escalation allowed
                if ctx.get("allowPrivilegeEscalation"):
                    profile.findings.append(Finding(
                        resource_id=profile.resource_id,
                        resource_name=f"{pod['name']}/{name}",
                        resource_type="Container",
                        issue="Container allows privilege escalation",
                        severity="HIGH",
                        risk_score=75,
                        recommendation="Set allowPrivilegeEscalation: false in securityContext"
                    ))

                # Writable root filesystem
                if not ctx.get("readOnlyRootFilesystem"):
                    profile.findings.append(Finding(
                        resource_id=profile.resource_id,
                        resource_name=f"{pod['name']}/{name}",
                        resource_type="Container",
                        issue="Container has writable root filesystem",
                        severity="MEDIUM",
                        risk_score=45,
                        recommendation="Set readOnlyRootFilesystem: true — use emptyDir volumes for writable paths"
                    ))

                # No resource limits
                if not container.get("resources", {}).get("limits"):
                    profile.findings.append(Finding(
                        resource_id=profile.resource_id,
                        resource_name=f"{pod['name']}/{name}",
                        resource_type="Container",
                        issue="Container has no resource limits",
                        severity="MEDIUM",
                        risk_score=40,
                        recommendation="Set CPU and memory limits to prevent resource exhaustion attacks"
                    ))

                # Latest image tag
                image = container.get("image", "")
                if image.endswith(":latest") or ":" not in image:
                    profile.findings.append(Finding(
                        resource_id=profile.resource_id,
                        resource_name=f"{pod['name']}/{name}",
                        resource_type="Container",
                        issue=f"Container uses unversioned image tag: {image}",
                        severity="MEDIUM",
                        risk_score=40,
                        recommendation="Pin image to a specific digest or version tag for reproducible deployments"
                    ))

        except Exception as e:
            profile.findings.append(Finding(
                resource_id=profile.resource_id,
                resource_name=pod["name"],
                resource_type="Pod",
                issue=f"Check error: {e}",
                severity="LOW",
                risk_score=0,
                recommendation="Review manually"
            ))

        if profile.findings:
            profiles.append(profile)

    return sorted(profiles, key=lambda p: p.total_risk_score(), reverse=True)


def check_rbac(bindings) -> List[RiskProfile]:
    profiles = []
    dangerous_roles = ["cluster-admin", "admin", "edit"]

    for binding in bindings:
        profile = RiskProfile(
            resource_id=binding["name"],
            resource_name=binding["name"],
            resource_type="RBACBinding"
        )

        try:
            role_name = binding["roleRef"]["name"]

            # Cluster-admin binding
            if role_name == "cluster-admin":
                profile.findings.append(Finding(
                    resource_id=binding["name"],
                    resource_name=binding["name"],
                    resource_type="RBACBinding",
                    issue=f"cluster-admin role bound to {[s['name'] for s in binding['subjects']]}",
                    severity="CRITICAL",
                    risk_score=100,
                    recommendation="Remove cluster-admin bindings. Use namespace-scoped roles with minimal permissions"
                ))

            # Default service account with elevated role
            for subject in binding.get("subjects", []):
                if subject.get("name") == "default" and role_name in dangerous_roles:
                    profile.findings.append(Finding(
                        resource_id=binding["name"],
                        resource_name=binding["name"],
                        resource_type="RBACBinding",
                        issue=f"Default service account bound to elevated role '{role_name}'",
                        severity="HIGH",
                        risk_score=85,
                        recommendation="Never bind elevated roles to the default service account"
                    ))

            # Wildcard rules
            for rule in binding.get("rules", []):
                if "*" in rule.get("verbs", []) and "*" in rule.get("resources", []):
                    profile.findings.append(Finding(
                        resource_id=binding["name"],
                        resource_name=binding["name"],
                        resource_type="RBACBinding",
                        issue="RBAC role has wildcard * verbs and resources",
                        severity="CRITICAL",
                        risk_score=95,
                        recommendation="Replace wildcard rules with specific verbs and resources"
                    ))

        except Exception as e:
            profile.findings.append(Finding(
                resource_id=binding["name"],
                resource_name=binding["name"],
                resource_type="RBACBinding",
                issue=f"Check error: {e}",
                severity="LOW",
                risk_score=0,
                recommendation="Review manually"
            ))

        if profile.findings:
            profiles.append(profile)

    return sorted(profiles, key=lambda p: p.total_risk_score(), reverse=True)


def check_secrets(secrets) -> List[RiskProfile]:
    profiles = []

    for secret in secrets:
        profile = RiskProfile(
            resource_id=f"{secret['namespace']}/{secret['name']}",
            resource_name=secret["name"],
            resource_type="Secret"
        )

        try:
            # Unencrypted secrets
            if not secret.get("encrypted"):
                profile.findings.append(Finding(
                    resource_id=profile.resource_id,
                    resource_name=secret["name"],
                    resource_type="Secret",
                    issue="Secret is not encrypted at rest",
                    severity="HIGH",
                    risk_score=75,
                    recommendation="Enable etcd encryption at rest or use an external secrets manager like AWS Secrets Manager or HashiCorp Vault"
                ))

        except Exception as e:
            profile.findings.append(Finding(
                resource_id=profile.resource_id,
                resource_name=secret["name"],
                resource_type="Secret",
                issue=f"Check error: {e}",
                severity="LOW",
                risk_score=0,
                recommendation="Review manually"
            ))

        if profile.findings:
            profiles.append(profile)

    return sorted(profiles, key=lambda p: p.total_risk_score(), reverse=True)


def check_namespaces(namespaces) -> List[RiskProfile]:
    profiles = []

    for ns in namespaces:
        profile = RiskProfile(
            resource_id=ns["name"],
            resource_name=ns["name"],
            resource_type="Namespace"
        )

        try:
            # No network policy
            if not ns.get("hasNetworkPolicy"):
                profile.findings.append(Finding(
                    resource_id=ns["name"],
                    resource_name=ns["name"],
                    resource_type="Namespace",
                    issue="Namespace has no NetworkPolicy — all pod-to-pod traffic is allowed",
                    severity="HIGH",
                    risk_score=80,
                    recommendation="Apply a default-deny NetworkPolicy and explicitly allow required traffic"
                ))

            # No resource quota
            if not ns.get("hasResourceQuota"):
                profile.findings.append(Finding(
                    resource_id=ns["name"],
                    resource_name=ns["name"],
                    resource_type="Namespace",
                    issue="Namespace has no ResourceQuota",
                    severity="LOW",
                    risk_score=25,
                    recommendation="Set ResourceQuota to prevent resource exhaustion from misconfigured workloads"
                ))

        except Exception as e:
            profile.findings.append(Finding(
                resource_id=ns["name"],
                resource_name=ns["name"],
                resource_type="Namespace",
                issue=f"Check error: {e}",
                severity="LOW",
                risk_score=0,
                recommendation="Review manually"
            ))

        if profile.findings:
            profiles.append(profile)

    return sorted(profiles, key=lambda p: p.total_risk_score(), reverse=True)