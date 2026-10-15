# The provisioning workflow contract — v1 (SSO-3719, epic SSO-3304)

**Audience: Thoryn engineers.** This is the INTERNAL contract between the Thoryn GitHub App (oauthy
`starter-orchestrator`, converge ADR 2026-10-13 Amendments 1, 5–7) and the reusable workflow
`thoryn-io/thoryn-cli/.github/workflows/provisioning.yml`. It is **not a customer authoring surface**: a customer
configures the workflow (README "Configure the provisioning workflow"), never writes one. The contract is pinned in code
by `cli/src/main/kotlin/com/devnow/thoryn/cli/cmd/provision/workflow/ProvisioningWorkflowContract.kt`, enforced by
`WorkflowCheck` (the engine behind `thoryn provision workflow check` and the dogfood conformance tests), and bumped
(`contractVersion`) when a rule changes what a valid stub or reusable workflow looks like.

## Why a workflow file exists at all

The job's own GitHub **OIDC token is the repository's identity** (exchanged by `thoryn login --connection` under the
workspace's workload identity trust), and the job's GitHub **environment is the review gate** the hub pins (a production
trust is pinned to a reviewed environment; the plan profile is keyed on an unprotected one — Amendments 5/6). Neither can
move into the App, which never holds a Thoryn credential. Everything else moved out of the customer's repository into
the reusable workflow. What a repository keeps is a **stub**.

## 1. What the App dispatches (`dispatch.*`)

The App dispatches the file at **`.github/workflows/thoryn-provisioning.yml`** (`ThorynFiles.WORKFLOW_PATH`) on the
default branch, in both modes, by `workflow_dispatch`:

| Input | Required | Type | Value |
|---|---|---|---|
| `mode` | yes | `choice` `[plan, apply]` | `plan` on a pull request touching `.thoryn/**`; `apply` on a push to the default branch |
| `head_sha` | yes | `string` | the commit to plan or apply (the PR head, or the pushed sha) |
| `check_run_id` | yes | `string` | the App's check run (*Thoryn provisioning plan* / *apply*) |
| `pr_number` | no (`default: ""`) | `string` | the pull request, plan only |

and requires of the dispatched workflow:

- `run-name` contains **`check-run:${{ inputs.check_run_id }}`** — how the App finds the run (`workflow_run.completed`)
  to complete its check run;
- the line **`# thoryn-provisioning: apply-job`** (`ThorynFiles.APPLY_JOB_MARKER`) is present iff the workflow applies —
  the App dispatches `apply` only when it sees it. In a stub the marker sits above the `uses:` job; the reusable workflow
  carries it on its own apply job;
- top-level **`permissions: {}`**; the job(s) declare their own;
- **`concurrency.group`** contains `${{ inputs.mode }}` and `cancel-in-progress: false` — a plan never waits on an
  apply, two applies never race, a held apply is never cancelled. The stub's top-level concurrency covers the called jobs
  (they are part of the caller's run), so the reusable workflow declares none;
- **no `secrets`** anywhere, and **no `${{ … }}` inside a `run:` block** (oauthy SSO-3635: a value interpolated into
  `run:` lands in the shell's source — every value reaches a script through `env:`).

## 2. The stub (`stub.*`) — the supported shape

```yaml
name: Thoryn provisioning
run-name: "Thoryn provisioning ${{ inputs.mode }} ${{ inputs.head_sha }} check-run:${{ inputs.check_run_id }}"
on:
  workflow_dispatch:
    inputs:          # exactly §1's four
concurrency:
  group: thoryn-provisioning-${{ inputs.mode }}
  cancel-in-progress: false
permissions: {}
jobs:
  # thoryn-provisioning: apply-job
  provisioning:
    uses: thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@cli-v0.36.0
    permissions: { id-token: write, checks: write, contents: read }
    with:
      mode: ${{ inputs.mode }}
      head_sha: ${{ inputs.head_sha }}
      check_run_id: ${{ inputs.check_run_id }}
      pr_number: ${{ inputs.pr_number }}
      plan-environment: <unprotected GitHub environment>
      apply-environment: <reviewed GitHub environment>
      issuer: https://auth.thoryn.io      # optional, and the other optional inputs of §3
```

- **one job**, carrying only `uses`, `with`, `permissions` (`name`/`if`/`needs` tolerated) — `runs-on`, `timeout-minutes`
  and the environments are inputs of the reusable workflow; steps and secrets have no place here;
- `uses:` is **`thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@<ref>`** with `<ref>` a `cli-v*` tag ≥
  **cli-v0.36.0** (the first release shipping the reusable workflow) or a full commit sha — a branch is refused (it moves
  under you). A `uses:` of any other workflow is **unverifiable**: the check says so and tells you to run it on that file;
- `with:` forwards the four dispatch inputs **verbatim** (`${{ inputs.<name> }}`), passes `plan-environment` and
  `apply-environment` as **different** literal environment names, and may pass any other input of §3 as a literal that
  satisfies its grammar; **a key that is not an input is refused**, named;
- job `permissions` are **exactly** `id-token: write`, `checks: write`, `contents: read` (what the called jobs declare;
  a called job can only lower what the caller grants). No `contents: write`: nothing is written back (§4);
- **no `secrets:`** on the job.

A stub pinned to a tag that does not exist yet fails at **dispatch time** with GitHub's "workflow file issue" (zero
jobs), not at merge time — which is why the first App dispatch after the merge that lands `provisioning.yml` needs the
release tag it pins to have been cut.

## 3. The reusable workflow (`reusable.*`) — the called side

`on: workflow_call` with exactly these inputs (`ProvisioningWorkflowContract.REUSABLE_INPUTS`):

| Input | Required | Default | Grammar | Purpose |
|---|---|---|---|---|
| `mode`, `head_sha`, `check_run_id`, `pr_number` | first three | `pr_number: ""` | forwarded `${{ inputs.<name> }}` | §1 |
| `plan-environment` | yes | — | GitHub environment name | the **unprotected** environment the plan job runs in — the trust's plan profile is keyed on it |
| `apply-environment` | yes | — | GitHub environment name | the **reviewed** environment the apply job runs in — required reviewers hold the run before any token can be minted; the trust pins it |
| `issuer` | no | `https://auth.thoryn.io` | `https://` origin | platform base issuer → `THORYN_ISSUER` / `THORYN_HUB` |
| `cli-version` | no | `""` | `cli-vX.Y.Z` | empty ⇒ **the release the workflow was called at** (see below) |
| `runs-on` | no | `ubuntu-latest` | a label, or a JSON array of labels | self-hosted pools; the runner needs bash, gh, jq, curl (Java is set up) |
| `timeout-minutes` | no | `30` | positive integer | each job |
| `config` | no | `.thoryn/workflow.yaml` | relative path | the run-time configuration (§5) |
| `consent-url` | no | `""` | `https://` base URL, no query/fragment | SSO-3723 — `THORYN_CONSENT_URL` for the CLI: a red job's `To fix — Option 2, in the browser:` link, `<url>/github/consent/run/<owner>/<repo>/<run_id>`; empty ⇒ §5 `consentUrl`, else the CLI commands alone |

Jobs **`plan`** and **`apply`**, each: `if: inputs.mode == '<mode>'`; `runs-on` from `inputs.runs-on`
(`startsWith(…, '[') && fromJSON(…) || …`); `timeout-minutes` from the input; **`environment: ${{ inputs.<mode>-environment }}`
— a called job's environment resolves against the CALLER**, so the caller's reviewers gate it and the caller's trust
pins it; permissions exactly §2's three; first step `actions/checkout` at `${{ inputs.head_sha }}`; then set up Java,
download the release's `thoryn.jar`, run **`thoryn provision workflow check --file <stub> --config <config> --output json`**
(the stub from `github.workflow_ref` — the CALLER's workflow path — the config from the input; a red check fails the job
with each fix named) and act on its `config` object: for every `files[]` entry `thoryn login --connection <connection>` then
`thoryn provision plan|apply --file <file>` (`apply --yes`, `--prune` / `--confirm` only as configured), the plan/apply
output into the step summary; **`THORYN_FIX_REQUEST`** on the sign-in/plan/apply step, **`THORYN_CONSENT_URL`** exported on it
from `consent-url` else the config's `consentUrl` (SSO-3723), and an
`actions/upload-artifact` (pinned to a commit) step `if: failure() && <fixRequest>` uploading **`thoryn-provision-request`**
(`if-no-files-found: ignore`, `retention-days: 7`); the apply job ends at **Applied** (no receipt, §4). The apply job
carries `# thoryn-provisioning: apply-job`.

**Pinning the CLI to the called ref.** GitHub gives a called job one reference to its own file: **`job.workflow_ref`**
— "the full ref of the workflow file that defines the current job; for jobs defined in a reusable workflow, this refers to
the reusable workflow file", e.g. `thoryn-io/thoryn-cli/.github/workflows/provisioning.yml@refs/tags/cli-v0.36.0`
(`job.workflow_sha` is its commit; `github.workflow_ref` / `github.job_workflow_sha` name the CALLER's workflow — the
latter is no longer documented). The workflow reads it through `toJSON(job)` (actionlint 1.7.12's schema predates the
property; the `job` context is small and secret-free) and, when the ref is `refs/tags/cli-v*`, downloads that release —
so one pin in the stub (`uses: …@cli-v0.36.0`) selects both the workflow and the CLI. Any other ref (`@main`, a sha)
falls back to the latest `cli-v*` release with a `::notice`. `cli-version` overrides either way. Not available on GHES
(the fallback applies).

## 4. Nothing is written back (`reusable.no-write-back`)

Per oauthy ADR `2026-10-15-platform-is-the-ledger-no-committed-provisioning-receipt` (SSO-3708; the orchestrator's
SSO-3717 shape): no `contents: write`, no `pull-requests`, no `git push` / `gh pr create`. Ownership is the platform's
`owner` relation, not a committed receipt. Removals are never automated unless the configuration says so (§5; both
toggles default off).

## 5. The run-time configuration — `.thoryn/workflow.yaml` (`config.*`)

Schema `cli/src/main/resources/examples/workflow.schema.json`; loader `WorkflowConfig` (unknown keys refused at every
level; each value's grammar checked). Absent ⇒ the built-in defaults. Keys: `apiVersion: thoryn.io/workflow/v1`,
`provider` (`github_actions` only — Forgejo is a recorded gap, see README), `files[] {file, connection}` (one or many; a
connection defaults to the `connection.json` beside its file), `env` (`THORYN_*` names only, not workflow-owned, never
credential-shaped; exported, never evaluated), `fixRequest` (default true), `consentUrl` (SSO-3723 — the browser
consent base URL, `https://` without query or fragment; `THORYN_CONSENT_URL` for the CLI when the `consent-url` input is
empty; default empty ⇒ the CLI commands alone), `apply.prune` / `apply.destroy` (default false) / `apply.confirm`
(workspace slug). The check also confirms every configured file is committed.

## 6. A hand-written workflow (`custom.*`) — unsupported

`thoryn provision workflow check` evaluates §1's rules plus one (`custom.jobs`: a job gated on each mode, in two different
environments, with `id-token: write` + `checks: write`, checking out `head_sha` first, uploading `thoryn-provision-request`
on failure) and labels the result **UNSUPPORTED**: this is what the App would need from it, not a shape Thoryn promotes.
The reason there is no script hook: the identity and the review gate must stay inside the reusable workflow, where the
contract can hold them. When configuration is not enough, file a product gap.

## Versioning

`contractVersion: 1`. The rule ids above (`dispatch.*`, `stub.*`, `reusable.*`, `config.*`, `custom.*`, `common.*`) are
the stable names the check prints and `--output json` carries.
