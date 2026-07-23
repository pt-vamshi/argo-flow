# Task 2 & 3: SSO + RBAC Implementation for L1/L2/L3

This document summarizes the complete implementation of SSO (Azure Entra ID) and RBAC model for L1/L2/L3 roles in Argo Workflows.

## Task 2: Adding SSO to Argo Workflows

### Overview
Argo Workflows is integrated with Azure Entra ID (hosted OIDC provider) for user authentication and identity-based access control. No in-cluster IdP required.

### Architecture

```
User (Azure Entra)
       ↓
   OIDC Login
       ↓
   Token + groups claim (contains security group GUIDs)
       ↓
   Argo Server (--auth-mode=sso)
       ↓
   Match RBAC rule annotations → Map to ServiceAccount
       ↓
   Kubernetes RBAC enforcement
```

### Components

#### 1. **Argo Server Configuration** 
File: `manifests/argo-workflows/argo-server-patch.yaml`

```yaml
args: ["server", "--auth-mode=sso", "--auth-mode=client", "--secure=false"]
```

- `--auth-mode=sso` — Enable Azure Entra OIDC login
- `--auth-mode=client` — Keep ServiceAccount token auth for strong audit trail
- `--secure=false` — HTTP (for local dev; use HTTPS in production)

#### 2. **SSO Configuration**
File: `manifests/argo-workflows/workflow-controller-configmap.yaml`

```yaml
sso:
  issuer: https://login.microsoftonline.com/{tenant-id}/v2.0
  clientId:
    name: argo-server-sso
    key: client-id
  clientSecret:
    name: argo-server-sso
    key: client-secret
  redirectUrl: http://localhost:2746/oauth2/callback
  rbac:
    enabled: true
  filterGroupsRegex:
    - "da9685fc-4f7a-4b8d-aec2-188338b1795b"   # L1 group GUID
    - "2c23e798-8303-45f9-ba95-ec3cd362b63d"   # L2 group GUID
    - "6faedd5d-be36-4c63-a7c9-57e7228aa423"   # L3 group GUID
  scopes:
    - openid
    - email
    - profile
  sessionExpiry: 240h
```

#### 3. **Sealed Secret**
File: `manifests/argo-workflows/argo-server-sso.sealedsecret.yaml`

Contains encrypted Entra credentials (client ID + secret). Decrypted by ArgoCD using SealedSecrets controller.

#### 4. **ServiceAccount Tokens**
File: `manifests/rbac/humans.yaml` (lines 181-213)

Three ServiceAccount token secrets for SSO delegation:
```yaml
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  annotations: { kubernetes.io/service-account.name: l1-user }
```

**Note:** Token name must be `{sa-name}.service-account-token` — Argo looks up this exact name.

### Setup Steps

1. **Register App in Entra** (one-time)
   - Go to entra.microsoft.com → App registrations
   - Create app: `argo-runbook-lab`
   - Add redirect URI: `http://localhost:2746/oauth2/callback`
   - Copy Application (client) ID and tenant ID

2. **Create Client Secret**
   - Certificates & secrets → New client secret
   - Copy the **Value**

3. **Configure Groups Claim**
   - Token configuration → Add groups claim → Security groups
   - Enable for ID + Access tokens

4. **Create Security Groups** (in Entra)
   - Create L1, L2, L3 groups
   - Copy their Object IDs (GUIDs)
   - Add users to appropriate groups

5. **Update Configuration Files**
   - `manifests/rbac/humans.yaml` — Update `rbac-rule` annotations with GUIDs
   - `manifests/argo-workflows/workflow-controller-configmap.yaml` — Update `issuer`, `filterGroupsRegex` with GUIDs

6. **Seal & Commit**
   ```bash
   make seal-secret CLIENT_ID=<id> CLIENT_SECRET=<secret>
   git add -A && git commit -m "sso: add azure entra configuration"
   git push
   ```

7. **Verify**
   ```bash
   make port-forward
   # Open http://localhost:2746
   # Click "Login" → Sign in with Entra account
   ```

### Security Notes

- **Audit Trail:** Under SSO mode, k8s audit log records the mapped ServiceAccount (e.g., `l1-user`), not the human user. The human identity lives in Argo Server logs.
- **Token-based Access:** `--auth-mode=client` stays enabled — CI/CD pipelines using ServiceAccount tokens still record the real caller in audit logs.
- **Network:** Requires cluster egress to `login.microsoftonline.com`.

---

## Task 3: Creating RBAC Model for L1, L2, L3

### Overview

Three-tier approval model for runbook operations:
- **L1** — Submit + view (no approval power)
- **L2** — Approve L1-tier workflows (default operations)
- **L3** — Approve L3-tier workflows (privileged operations, e.g., node drains, multi-cluster changes)

### Key Design

#### Roles are Cluster-Wide (ClusterRole + ClusterRoleBinding)

RBAC is now enforced with ClusterRoles, granting permissions across all namespaces. Kubernetes has no object-level RBAC, so you either trust a tier across the board or don't.

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole  # ← Cluster-wide, not namespace-scoped
metadata:
  name: runbooks-l1
rules:
  - resources: ["workflows"]
    verbs: ["create", "get", "list", "watch"]  # NO update/patch
```

#### Human Identities

ServiceAccounts in `argo` namespace:
- `l1-user` → Entra L1 group
- `l2-approver` → Entra L2 group
- `l3-approver` → Entra L3 group

Mapped via `rbac-rule` annotations matching Entra group GUIDs (from token's `groups` claim).

### Permissions Matrix

| Permission | L1 | L2 | L3 |
|-----------|----|----|----| 
| Create workflows | ✓ | ✓ | ✓ |
| View workflows/pods/logs | ✓ | ✓ | ✓ |
| Update/patch workflows (resume) | ✗ | ✓ | ✓ |
| Delete workflows | ✗ | ✗ | ✓ |
| View WorkflowTemplates | ✓ | ✓ | ✓ |
| Update WorkflowTemplates | ✗ | ✗ | ✗ |

### Implementation

File: `manifests/rbac/humans.yaml`

#### 1. ServiceAccounts (lines 14-45)

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: l1-user
  namespace: argo
  annotations:
    workflows.argoproj.io/rbac-rule: "'da9685fc-4f7a-4b8d-aec2-188338b1795b' in groups"
    workflows.argoproj.io/rbac-rule-precedence: "1"
```

The `rbac-rule` uses Argo's expression language to match Entra group GUIDs.

#### 2. ClusterRole: `runbooks-l1` (lines 47-75)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: runbooks-l1
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["workflows"]
    verbs: ["create", "get", "list", "watch"]  # Read + create only
  - apiGroups: [""]
    resources: ["pods", "pods/log"]
    verbs: ["get", "list", "watch"]
```

- Can submit workflows
- Can read pods/logs across all namespaces
- **Cannot** resume (no `update`/`patch`)

#### 3. ClusterRole: `runbooks-l2` (lines 77-95)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: runbooks-l2
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["workflows"]
    verbs: ["create", "get", "list", "watch", "update", "patch"]  # Can resume
```

- Everything L1 has, plus
- Can `update`/`patch` workflows (resume/approve suspended workflows)
- Cluster-wide scope

#### 4. ClusterRole: `runbooks-l3` (lines 97-115)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: runbooks-l3
rules:
  - apiGroups: ["argoproj.io"]
    resources: ["workflows"]
    verbs: ["create", "get", "list", "watch", "update", "patch", "delete"]  # Can delete
```

- Everything L2 has, plus
- Can `delete` workflows
- Cluster-wide scope

#### 5. ServiceAccount Tokens (lines 181-213)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: l1-user.service-account-token
  namespace: argo
  annotations: { kubernetes.io/service-account.name: l1-user }
type: kubernetes.io/service-account-token
```

Required for Argo Server SSO delegation. Token names must match the exact pattern `{sa-name}.service-account-token`.

### Approval Flow

```
1. L1 user submits workflow via Argo UI/CLI
   └─> Workflow created in `suspended` state (orchestrated in template)

2. Workflow notifies L2 approver (via Slack/email webhook, external system)

3. L2 user reviews and resumes workflow
   └─> Argo Server calls `argo resume` → PATCH on Workflow
   └─> RBAC check: L2 has `patch workflows` → allowed
   └─> Workflow proceeds

4. If L3-tier operations are needed
   └─> L3 user alone can approve (L2 RBAC forbids it)
   └─> Workflow runs with L3 runner ServiceAccount
```

### Testing

Run the RBAC test script:
```bash
./scripts/test-rbac.sh
```

Verifies each tier's permissions:
- L1 can create/view, cannot resume
- L2 can create/resume
- L3 can create/resume/delete

### Files Modified

- `manifests/rbac/humans.yaml` — Converted Role → ClusterRole for all tiers, simplified namespace separation
- `manifests/argo-workflows/workflow-controller-configmap.yaml` — SSO config (already present)
- `manifests/argo-workflows/argo-server-patch.yaml` — Server args (already present)
- `manifests/argo-workflows/argo-server-sso.sealedsecret.yaml` — Entra secrets (already present)

### Workflow Templates

Runbook templates are pre-defined in `manifests/runbooks/`:
- `l1-*.yaml` — L1 tier operations (e.g., get logs, check pod status)
- `l2-*.yaml` — L2 tier operations (e.g., restart deployment)
- `l3-*.yaml` — L3 tier operations (e.g., drain nodes, scale persistent volumes)

Each template specifies its `serviceAccountName`, pinned via `templateReferencing: Secure` in the workflow controller config. This prevents L1 from escalating to L3 runner credentials.

---

## Summary

| Aspect | Implementation |
|--------|---|
| **Authentication** | Azure Entra OIDC (SSO) with security group-based RBAC |
| **Identity Mapping** | Entra groups → ServiceAccounts → ClusterRoles |
| **Scope** | Cluster-wide (ClusterRole + ClusterRoleBinding) |
| **Approval Gate** | RBAC `patch workflows` permission (no separate "approve" API) |
| **Audit Trail** | k8s audit log records ServiceAccount; human identity in Argo logs |
| **Fallback** | ServiceAccount token auth (--auth-mode=client) for CI/CD |

---

## Quick Reference

### Deploy
```bash
make bootstrap              # Cluster + ArgoCD + SealedSecrets
make seal-secret ...        # Encrypt Entra creds
make port-forward          # Argo UI (http://localhost:2746)
```

### Verify
```bash
./scripts/test-rbac.sh     # Test L1/L2/L3 permissions
kubectl logs -n argo -l app=argo-server -f  # Monitor SSO login
```

### Add User to Tier
1. Add user to Entra security group (L1, L2, or L3)
2. User logs in; Argo maps them to corresponding ServiceAccount
3. RBAC is enforced on next action

---

## References

- Full Entra setup: `docs/entra-setup.md`
- RBAC definitions: `manifests/rbac/humans.yaml`
- SSO config: `manifests/argo-workflows/workflow-controller-configmap.yaml`
- Runbook templates: `manifests/runbooks/`
