# An application in Kubernetes fetches its own Thoryn client secret

> **DEPRECATED — product-owner decision 2026-10-25 (oauthy SSO-3951; this path is removed by SSO-3953).** Thoryn owns an
> application's client-secret lifecycle (mint, show once, rotate with the 24 h overlap, revoke, audit); **the customer
> owns delivery** into its runtime. Trusting individual pods to pull their sign-in secret (the `kubernetes` trust and
> these init containers) couples Thoryn to the customer's deployment platform and is no longer the customer story. New
> deployments: a person mints the secret — `thoryn clients rotate-secret <clientId> --secret-file ./s --confirm
> <workspace-slug>` — and stores it in the secret manager or an **operator-created Kubernetes Secret** the pod mounts
> (`kubectl -n <ns> create secret generic <name> --from-file=client-secret=./s`, then delete the local file; rotate the
> same way, then roll the deployment inside the 24 h overlap). The runbook is oauthy
> `docs/content/guides/application-credentials-ladder.mdx`, "A client secret in your secret store"; the forge's own
> migration off this manifest is thoryn-cicd SSO-3952. With provisioning-as-code, declare the application with **no
> `secretSink`** (the default, `customerManaged`, SSO-3954) instead of `workloadPull`; `thoryn provision` still converges a
> `workloadPull` sink, with a deprecation warning, until SSO-3953. What follows is kept for the record.

SSO-3684 (parent [SSO-3678](https://thoryn.atlassian.net/browse/SSO-3678), epic SSO-3304). The hub and
product-api half is oauthy #4095; the design is oauthy ADR
`adrs/2026-10-14-kubernetes-workload-identity-and-runtime-credential-pull.md`, the user guide the
Kubernetes section of `docs/content/guides/workload-identity-github-actions.mdx` (published at
thoryn.org/docs). This directory is that guide's manifest, complete and applyable.

## The problem it removes

Software that can only consume a `client_secret` — oauth2-proxy, Forgejo's OIDC login, Grafana — in front
of Thoryn SSO used to need a human (or a CI job) to mint the secret and copy it into the cluster: three
hand-offs and a copy of a credential in a CI secret store. Here the **pod pulls the secret itself** with
the token Kubernetes already gives it. No client secret crosses a repository, a CI secret store or a person.

```
projected ServiceAccount token  ──►  init container 1: thoryn login --connection /etc/thoryn/connection.json
   (iss = the cluster,                   (exchanged under a `kubernetes` workload identity trust;
    sub = system:serviceaccount:forge:forge-oauth2-proxy,   the session goes to the RAM volume /thoryn-session)
    aud = the trust's audience)     ──►  init container 2: thoryn clients rotate-secret $APP_CLIENT_ID --secret-file /shared/client-secret
                                    ──►  oauth2-proxy --client-secret-file=/shared/client-secret
```

## Files

| File | What it is |
|---|---|
| `deployment.yaml` | ServiceAccount + ConfigMap (the connection contract) + Deployment: the projected token volume (`audience` = the trust's audience, `expirationSeconds: 3600`), the two Thoryn init containers (`thoryn-login`, then `thoryn-client-secret`) sharing the in-memory `/thoryn-session` volume, the in-memory `/shared` volume, oauth2-proxy reading the file. |
| `connection.json` | The connection contract the init container signs in with — what `thoryn workload-identity trusts create --provider kubernetes` prints. Token source: the projected token FILE. It holds no secret. |

## Steps

1. **Create the trust** (an environment manager; `tenant:workload-identity.write`):

   ```bash
   # A PRIVATE cluster (k3s, kind, an on-prem cluster whose issuer resolves nowhere outside): pin its
   # PUBLIC key set. A managed cloud cluster (EKS, GKE, AKS) publishes its issuer — skip this and --jwks-file.
   kubectl get --raw /openid/v1/jwks > cluster-jwks.json

   thoryn workload-identity trusts create --provider kubernetes --name forge-oauth2-proxy \
     --issuer "$(kubectl get --raw /.well-known/openid-configuration | jq -r .issuer)" \
     --namespace forge --service-account forge-oauth2-proxy \
     --jwks-file cluster-jwks.json \
     --scope tenant:applications.write --confirm-production
   ```

   A production trust must pin **both** the namespace and the service account (the CLI refuses
   `--confirm-production` without them, as the API refuses `production_requires_service_account`). It
   prints the `clientId` (`wi_…`), the `audience`, and the `connection.json` — paste it into the ConfigMap.

2. **Let the trust's client rotate the application's secret** — `manager` on that one application:

   ```bash
   thoryn access grant --subject client:wi_9a8b7c6d5e4f3a2b1c0d9e8f --relation manager \
     --object application:7f1c2d3e-4a5b-6c7d-8e9f-0a1b2c3d4e5f
   ```

   With provisioning-as-code (SSO-3921), declare it on the application instead — `thoryn provision apply`
   converges this grant, and a CI apply that creates the application discards the minted secret rather than
   needing somewhere to deliver it (the pod's rotation replaces it):

   ```yaml
   - kind: application
     name: forge-oauth2-proxy
     spec: { displayName: "Forge oauth2-proxy", grantTypes: [authorization_code], redirectUris: ["https://forge.example/oauth2/callback"] }
     secretSink: { kind: workloadPull, trust: forge-oauth2-proxy }   # the trust of step 1, by name
   ```

3. **Pin the image** — `ghcr.io/thoryn-io/thoryn-cli`, public, multi-arch, published by every `cli-v*`
   release. There is no `:latest`: use a released `<version>` and its **digest**, which exists only once
   that release has pushed it. Look it up, verify the signature, then pin `…:<version>@sha256:<digest>`:

   ```bash
   docker buildx imagetools inspect ghcr.io/thoryn-io/thoryn-cli:<version>     # the "Digest:" line
   cosign verify ghcr.io/thoryn-io/thoryn-cli@sha256:<digest> \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-identity-regexp '^https://github\.com/thoryn-io/thoryn-cli/\.github/workflows/release\.yml@refs/(tags/cli-v.+|heads/main)$'
   ```

   (The release run's summary also prints the exact reference it pushed.)

4. **Edit and apply** `deployment.yaml`: the `# <-` values (service account name / namespace must
   equal the trust's pins; the image digest; `APP_CLIENT_ID` is the application; `--confirm` takes your
   workspace slug because the application is in production) and the `audience:` of the projected
   volume (the trust's audience, exactly). Then `kubectl apply -f deployment.yaml`.

The init containers run once per pod start. **Rotation is a restart**: `rotate-secret` keeps the previous
secret valid for 24 hours, so a rolling restart never breaks a running replica. If a private cluster
rotates its signing key, re-create the trust with the new `--jwks-file`.

## What the hub checks (and how a refusal reads)

The hub accepts the pod's token only when its signature verifies against the cluster's keys, `iss` is the
pinned issuer, `aud` is the trust's audience, it is unexpired and unused, `sub` is exactly
`system:serviceaccount:<namespace>:<serviceAccount>` for the pinned names, and the `kubernetes.io` claim
names the same two (a legacy Secret-based token has no such claim and is refused). Every refusal is the
same `401 invalid_client`; the exact reason is in the workspace audit log
(`thoryn audit query --event-type workload_identity.exchange_failed`). The CLI prints what it sent and the
pod's own identity (the public claims — never the token), and names the difference it can see when the
connection carries the `auth.kubernetes` pins:

```text
Sign-in failed: the platform refused the workload identity exchange (HTTP 401: invalid_client).
…
This pod (claims of its projected ServiceAccount token; the token itself is not shown):
  iss                  https://kubernetes.default.svc.cluster.local
  sub                  system:serviceaccount:staging:forge-oauth2-proxy
  aud                  https://thoryn.auth.thoryn.io
  namespace            staging
  service account      forge-oauth2-proxy

Differences found locally:
  - namespace: the trust pins 'forge'; this pod runs in 'staging'.
```

## Notes

- The image is `gcr.io/distroless/cc-debian12:nonroot` plus the `thoryn` binary: no shell, uid/gid
  `65532`, `ENTRYPOINT ["/usr/local/bin/thoryn"]` — so each step passes the CLI's arguments as `args:`, and
  `login && rotate-secret` is two init containers rather than one `sh -c`. It has no OS keychain, so both
  set the explicit file-store opt-in (`THORYN_CI_PLAINTEXT_TOKENS=1`, `THORYN_TOKEN_FILE` on the session
  volume) and each logs one `WARNING: Using plaintext file token store…` line announcing it.
- `/thoryn-session` holds the session the two steps share: a 15-minute workload-identity token and its
  DPoP key, on a RAM volume only the init containers mount. It is gone with the pod.
- `/shared` is an `emptyDir` with `medium: Memory`: the secret lives in RAM for the pod's lifetime and is
  gone with the pod. Mount it read-only in the application.
- The trust's scopes need only `tenant:applications.write`; the token the pod obtains lasts 15 minutes and
  is used once, for the rotation.
