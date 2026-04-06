# mock_data.py
# Simulates Kubernetes cluster data.
# K8s security model centers on pods, RBAC, secrets, and network policies.

def get_mock_pods():
    return [
        {
            "name": "frontend-pod",
            "namespace": "production",
            "containers": [
                {
                    "name": "frontend",
                    "image": "nginx:latest",
                    "securityContext": {
                        "runAsRoot": True,
                        "privileged": False,
                        "allowPrivilegeEscalation": True,
                        "readOnlyRootFilesystem": False
                    },
                    "resources": {
                        "limits": None
                    }
                }
            ],
            "hostNetwork": False,
            "hostPID": False,
            "serviceAccountName": "default"
        },
        {
            "name": "backend-pod",
            "namespace": "production",
            "containers": [
                {
                    "name": "backend",
                    "image": "myapp:1.2.3",
                    "securityContext": {
                        "runAsRoot": False,
                        "privileged": True,
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True
                    },
                    "resources": {
                        "limits": {"cpu": "500m", "memory": "128Mi"}
                    }
                }
            ],
            "hostNetwork": True,
            "hostPID": False,
            "serviceAccountName": "backend-sa"
        },
        {
            "name": "monitoring-pod",
            "namespace": "monitoring",
            "containers": [
                {
                    "name": "prometheus",
                    "image": "prom/prometheus:v2.40.0",
                    "securityContext": {
                        "runAsRoot": False,
                        "privileged": False,
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True
                    },
                    "resources": {
                        "limits": {"cpu": "1000m", "memory": "512Mi"}
                    }
                }
            ],
            "hostNetwork": False,
            "hostPID": False,
            "serviceAccountName": "monitoring-sa"
        }
    ]

def get_mock_rbac():
    return [
        {
            "name": "admin-binding",
            "namespace": "production",
            "kind": "ClusterRoleBinding",
            "roleRef": {
                "name": "cluster-admin",
                "kind": "ClusterRole"
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": "default",
                    "namespace": "production"
                }
            ]
        },
        {
            "name": "developer-binding",
            "namespace": "production",
            "kind": "RoleBinding",
            "roleRef": {
                "name": "edit",
                "kind": "ClusterRole"
            },
            "subjects": [
                {
                    "kind": "User",
                    "name": "developer@company.com"
                }
            ]
        },
        {
            "name": "wildcard-binding",
            "namespace": "default",
            "kind": "ClusterRoleBinding",
            "roleRef": {
                "name": "wildcard-role",
                "kind": "ClusterRole"
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": "legacy-sa",
                    "namespace": "default"
                }
            ],
            "rules": [
                {
                    "verbs": ["*"],
                    "resources": ["*"],
                    "apiGroups": ["*"]
                }
            ]
        }
    ]

def get_mock_secrets():
    return [
        {
            "name": "db-credentials",
            "namespace": "production",
            "type": "Opaque",
            "data": {
                "password": "cGFzc3dvcmQxMjM=",
                "username": "YWRtaW4="
            },
            "encrypted": False
        },
        {
            "name": "api-key",
            "namespace": "production",
            "type": "Opaque",
            "data": {
                "key": "c2VjcmV0a2V5MTIz"
            },
            "encrypted": False
        },
        {
            "name": "tls-cert",
            "namespace": "production",
            "type": "kubernetes.io/tls",
            "data": {},
            "encrypted": True
        }
    ]

def get_mock_network_policies():
    return [
        {
            "name": "backend-policy",
            "namespace": "production",
            "podSelector": {"matchLabels": {"app": "backend"}},
            "ingress": [{"from": [{"podSelector": {"matchLabels": {"app": "frontend"}}}]}],
            "egress": []
        }
    ]

def get_mock_namespaces():
    return [
        {
            "name": "production",
            "hasNetworkPolicy": True,
            "hasResourceQuota": False,
            "hasLimitRange": False
        },
        {
            "name": "default",
            "hasNetworkPolicy": False,
            "hasResourceQuota": False,
            "hasLimitRange": False
        },
        {
            "name": "monitoring",
            "hasNetworkPolicy": False,
            "hasResourceQuota": True,
            "hasLimitRange": True
        }
    ]