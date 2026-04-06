# k8s_data.py
# Real Kubernetes API calls — replaces mock_data.py when credentials are configured.
# Uses the kubernetes Python client library.

from kubernetes import client, config

def get_k8s_pods():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    pods = []

    for pod in v1.list_pod_for_all_namespaces().items:
        containers = []
        for container in pod.spec.containers:
            ctx = container.security_context or {}
            containers.append({
                "name": container.name,
                "image": container.image,
                "securityContext": {
                    "runAsRoot": ctx.run_as_user == 0 if ctx.run_as_user is not None else False,
                    "privileged": ctx.privileged or False,
                    "allowPrivilegeEscalation": ctx.allow_privilege_escalation or False,
                    "readOnlyRootFilesystem": ctx.read_only_root_filesystem or False
                },
                "resources": {
                    "limits": container.resources.limits if container.resources else None
                }
            })

        spec = pod.spec
        pods.append({
            "name": pod.metadata.name,
            "namespace": pod.metadata.namespace,
            "containers": containers,
            "hostNetwork": spec.host_network or False,
            "hostPID": spec.host_pid or False,
            "serviceAccountName": spec.service_account_name or "default"
        })

    return pods


def get_k8s_rbac():
    config.load_kube_config()
    rbac = client.RbacAuthorizationV1Api()
    bindings = []

    for binding in rbac.list_cluster_role_binding().items:
        subjects = []
        for subject in (binding.subjects or []):
            subjects.append({
                "kind": subject.kind,
                "name": subject.name,
                "namespace": subject.namespace
            })

        bindings.append({
            "name": binding.metadata.name,
            "namespace": binding.metadata.namespace or "cluster",
            "kind": "ClusterRoleBinding",
            "roleRef": {
                "name": binding.role_ref.name,
                "kind": binding.role_ref.kind
            },
            "subjects": subjects,
            "rules": []
        })

    return bindings


def get_k8s_secrets():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    secrets = []

    for secret in v1.list_secret_for_all_namespaces().items:
        secrets.append({
            "name": secret.metadata.name,
            "namespace": secret.metadata.namespace,
            "type": secret.type,
            "data": dict(secret.data or {}),
            "encrypted": False
        })

    return secrets


def get_k8s_namespaces():
    config.load_kube_config()
    v1 = client.CoreV1Api()
    networking = client.NetworkingV1Api()
    namespaces = []

    network_policies = networking.list_network_policy_for_all_namespaces().items
    ns_with_policies = set(np.metadata.namespace for np in network_policies)

    for ns in v1.list_namespace().items:
        name = ns.metadata.name
        namespaces.append({
            "name": name,
            "hasNetworkPolicy": name in ns_with_policies,
            "hasResourceQuota": False,
            "hasLimitRange": False
        })

    return namespaces