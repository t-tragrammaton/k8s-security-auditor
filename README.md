# Kubernetes Security Auditor

A Python security tool that audits Kubernetes clusters for misconfigurations across pods, RBAC bindings, secrets, and namespaces. Uses numeric risk scoring to surface compounding issues — a pod with six security violations scores higher than a single critical finding in isolation.

## What it checks

### Pods & Containers
| Check | Severity | Risk Score |
|---|---|---|
| Container running in privileged mode | CRITICAL | 100 |
| Pod with hostNetwork access | CRITICAL | 95 |
| Pod with hostPID access | CRITICAL | 95 |
| Container runs as root | HIGH | 80 |
| Container allows privilege escalation | HIGH | 75 |
| Unencrypted secrets at rest | HIGH | 75 |
| Writable root filesystem | MEDIUM | 45 |
| No resource limits | MEDIUM | 40 |
| Unversioned image tag | MEDIUM | 40 |
| Default service account in use | MEDIUM | 50 |

### RBAC
| Check | Severity | Risk Score |
|---|---|---|
| cluster-admin role binding | CRITICAL | 100 |
| Wildcard verbs and resources | CRITICAL | 95 |
| Default service account with elevated role | HIGH | 85 |

### Namespaces
| Check | Severity | Risk Score |
|---|---|---|
| No NetworkPolicy — all traffic allowed | HIGH | 80 |
| No ResourceQuota | LOW | 25 |

## Why Kubernetes security is different

**Privileged containers are container escapes.** A privileged container has full access to the host kernel. An attacker who compromises a privileged container owns the node.

**hostNetwork breaks isolation.** Pods with hostNetwork share the host's network namespace — they can see and interact with all traffic on the node, including other pods and host services.

**cluster-admin is the blast radius maximizer.** Any workload or service account with cluster-admin can read all secrets, modify any resource, and pivot to any namespace in the cluster.

**Default service account is a lateral movement vector.** The default service account exists in every namespace and is automatically mounted into pods. If it has elevated RBAC permissions, every pod in that namespace inherits them.

**Secrets are not encrypted by default.** Kubernetes stores secrets in etcd as base64-encoded strings, not encrypted. Without etcd encryption at rest or an external secrets manager, any etcd access means full secret exposure.

## Output

Prints findings to terminal sorted by total risk score and saves HTML and JSON reports to the output/ folder.

## How to run it

**1. Clone the repo**

`git clone https://github.com/t-tragrammaton/k8s-security-auditor.git`

`cd k8s-security-auditor`

**2. Install dependencies**

`pip install kubernetes`

**3. Run with mock data**

`python main.py`

**4. Run against a live cluster**

Set `USE_MOCK_DATA = False` in `main.py`, ensure your kubeconfig is configured:

`kubectl cluster-info`

`python main.py`

## Project structure

- `auditor/mock_data.py` — Simulated cluster data for local testing
- `auditor/k8s_data.py` — Live Kubernetes API calls via python-kubernetes client
- `auditor/checks.py` — Security checks with risk scoring
- `auditor/report.py` — HTML report generator
- `main.py` — Entry point

## Status

- [x] Pod and container security context checks
- [x] RBAC binding analysis
- [x] Secret encryption status
- [x] Namespace network policy and quota checks
- [x] Numeric risk scoring with compounding
- [x] HTML and JSON report output
- [x] Live Kubernetes API integration ready
- [ ] PodSecurityAdmission policy gap analysis
- [ ] Ingress security configuration checks
- [ ] Image vulnerability scanning integration
- [ ] CIS Kubernetes Benchmark alignment