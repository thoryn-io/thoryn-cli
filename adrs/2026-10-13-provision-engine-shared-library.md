# The provisioning engine is a library module of thoryn-cli; it ships inside the CLI and is published only when an in-process consumer exists

Jira: SSO-3662 (epic SSO-3087) · engine changes it lifts: SSO-3659 (thoryn-cli#104) · the consumer that
shaped it: SSO-3665 (the App dispatches a job; the job runs this CLI's Action)

Status: **Accepted** — product-owner decision 2026-10-13: `engine/` module in thoryn-cli; #105 (SSO-3435)
merged first by settlement, this PR rebased over it. Child of oauthy's
`adrs/2026-10-13-provisioning-as-code-converge-github-app-and-fga-ownership.md` §3, which settled THAT the
engine becomes a shared library and left WHERE it lives to "an ADR after a spike". This is that ADR; the
spike is the measurements below. Every number is labelled **ran** (a command run on 2026-10-13 against
`thoryn-cli` at `2a5b9fc` (main) and at `f2111fe` (#104's head), and `oauthy` at `07374e9c1`) or **read**
(a file or document read).

## Context

### Who consumes the engine — the frame changed during the spike

The Story (and the first cut of this spike) assumed two in-process consumers: the CLI and oauthy's
starter-orchestrator (the Thoryn GitHub App) calling the engine from a webhook. **SSO-3665, settled
2026-10-13, removed the second one:** the App cannot obtain the repository's workload-identity token outside
a GitHub Actions job (the trust pins the reviewed `production` environment, so the token exists only inside
an approved job), and the decision is that **the App dispatches a `workflow_dispatch` job in the customer's
repository — plan on pull requests, apply in the `production` environment — and that job is the OIDC
principal.** The job runs **thoryn-cli's composite Action**, which (read: `.github/actions/provision/action.yml`)
downloads the released `thoryn.jar` from a `cli-v*` release and runs `thoryn provision plan | apply`.

So the engine's first consumer is **this repository's own released jar**, and the orchestrator needs the
engine neither on its hot path nor at all today. That decides two things below: the home (the engine's
only consumer is the CLI, so it lives with the CLI) and the publication (there is nothing to publish FOR
yet, so the module is made publishable and not published).

### What the engine is (read; on #104, the branch SSO-3659 is landing)

`thoryn provision plan | apply | destroy | import` is driven by `ProvisionEngine` (1,580 lines on #104, up
from 1,095 on main — SSO-3659 added `Access`/`Reach`, the ownership `gate()`, `ChangeAction.ERROR`,
`import()`, the receipt `subject`, and the one-owner guard fed by `PeerReceipts`), `ProvisionFile` +
`provision.schema.json` and `ProvisionReceipt`. The 580-line picocli `ProvisionCommand` beside them is the
front end; `PeerReceipts` (file system + HTTPS) is "the CLI-side half of the guard: the engine only ever
sees the parsed receipts" (its own KDoc) and stays in the CLI.

Two assumptions in the Story turned out differently and matter: **thoryn-cli is Maven, not Gradle**
(`pom.xml` + `mvnw`, one module, whose pom says the artifact is "never install/deploy'd"); and **the
engine already runs on Jackson 3** (`tools.jackson.*` 3.2.2, read from its imports), the line oauthy's
Spring Boot 4 services run on (oauthy BOM `jackson3.version` 3.2.3). The "oauthy pins Jackson 2.22.x"
concern is about `com.fasterxml.jackson` 2.x, which the engine does not use.

### The coupling that had to be cut — identical for either home (ran: grep over the engine files, main AND #104)

The engine reached into the CLI through **nine symbols**, none about provisioning. #104 added **no new one**;
it added one more product-api call (`listMyAccess`, `GET /api/v1/access/mine`, scope `tenant:access.read`
— NOT `/api/v1/fga/check`, per Amendment 2 of the parent ADR).

| CLI symbol the engine used | What it is | Where it went |
|---|---|---|
| `api.ProductApiClient` (1,232 lines; JDK HttpClient + `Tokens` + `DpopSession`) | how the CLI talks to product-api | **`ProvisionApi` port** — 38 methods, signatures lifted verbatim (37 + `listMyAccess`); `ProductApiClient : ProvisionApi` |
| `api.ProductApiException` | the error the engine branches on (`httpStatus`, `errorCode`) | moved into the library; the CLI keeps a `typealias` |
| `cmd.AccessCommand` — 7 constants + 4 validators | the `<type>:<id>` grant grammar | **`AccessRefs`** in the library; `AccessCommand` delegates |
| `cmd.DnsRecord`, `cmd.CustomDomainView` | parsed custom-domain state | moved into the library; the CLI keeps `typealias`es |
| `cmd.DomainWaiter.NOT_ENTITLED / NO_ACCESS / problemReason`, `cmd.DomainCommand.reasonText` | four sentences the engine prints | **`CustomDomainMessages`**; the CLI delegates |
| `cmd.SecretIo` via `SecretSink.toSecretIo` | **the ONE TTY site** (`System.console`, `--secret-file`) | **left in the CLI** as `CliSecretSink`; the library's `SecretSink` is the interface only |
| `config.ThorynConfig.PRODUCTION_ENV_SLUG` | `"production"` | `ProvisionEngine.PRODUCTION_ENV_SLUG` |

picocli: zero references in the engine files (only `ProvisionCommand` imports it). TTY: exactly the one
site above. `System.out` / `System.err`: constructor defaults only.

After the cut the library is **2,410 lines in 7 files, 38 classes, a 159 KB jar** (on #104), and its
compile-scope tree is (ran: `dependency:tree`) `kotlin-stdlib`, `kotlin-reflect`, `jackson-databind` /
`-core` / `-module-kotlin` / `-dataformat-yaml` 3.2.x, `snakeyaml-engine`, and `jackson-annotations` 2.22
(Jackson 3's own transitive). **No HTTP client, no kotlinx, no Spring, no picocli.** The CLI consumes it as
a reactor sibling; `./mvnw -B verify` at the root: **engine 3 ArchUnit rules green, CLI 910 tests green**
(893 on main + #104's 17). Exactly **one test changed beyond import lines** —
`CiProvisionFileConformanceTest.requestableTenantScopes()` walked `<repo>/src/main` and now walks
`cli/src/main` + `engine/src/main`; **no assertion changed**. 17 files gained import lines (the engine's
package is `com.devnow.thoryn.provision`); `git status`: 242 pure renames (`src/` → `cli/src/`), 29
renamed-and-modified, 4 modified, 9 added.

### Candidate 1 — oauthy `core/lib/provision` (ran, on a throwaway copy of the extracted module)

- **Compiles** as a Spring-free module on the `thoryn-bom` parent (`./mvnw -pl core/lib/provision -am
  compile`: Kotlin 2.4.20, Jackson 3.2.3). The orchestrator **compiles against it in-reactor** (a spike
  class calling `ProvisionEngine(...).plan(ProvisionFile.parse(...))`). Nothing structural prevents it;
  the pom is the `core/lib/dsar` shape.
- **Publication** (read: `.github/workflows/shared-libs-publish.yml`): two `-pl` lists deploying **16
  artifacts at one version** to `maven.pkg.github.com/thoryn-io/oauthy` on a `libs-v*` tag or by dispatch.
  **Ran:** oauthy has **zero `libs-v*` tags**; the workflow has run **5 times, all `workflow_dispatch`, all
  SNAPSHOT, the last on 2026-06-13**.
- **Consumption by thoryn-cli:** a `<repository>` on a **private** repository's packages. GitHub Packages
  Maven needs a token for ANY read (read: the GitHub docs — "You need an access token to publish, install,
  and delete private, internal, and public packages"; **ran:** an anonymous GET on `maven.pkg.github.com`
  answers 401). That puts an org PAT (classic, `read:packages` — the only kind GitHub Packages accepts) on
  `ci.yml` (2 `mvnw` invocations), `release.yml` (3: `verify`, the 4-OS native matrix, `jar`), **every
  from-source build of a PUBLIC repository**, and makes **fork pull requests unbuildable**.
- **Release coupling:** an engine change = oauthy PR → `libs-v*` tag → publish → thoryn-cli bump PR →
  `cli-v*`. **Ran:** the engine package received **13 commits between 2026-09-09 and 2026-10-09**, every
  one from a CLI Story (SSO-2952, 3088, 3089, 3094, 3100, 3104, 3113, 3119, 3182, 3413, 3414, 3430, 3568)
  — and #104 (SSO-3659) is the 14th; thoryn-cli cut **45 `cli-v*` releases between 2026-09-08 and
  2026-09-30 (33 in the last 30 days)**. The engine's spec (schema, verbs; epic SSO-3087), its 11 test
  classes and `FakeProductApi` are in thoryn-cli; in this home the code would be a repository away from
  both, and a CLI test could see an engine fix only after a publish.
- **And, after SSO-3665, no consumer at all in oauthy** — the orchestrator would import a library it
  never calls.

### Candidate 2 — a library module inside thoryn-cli (ran, branch `feat/sso-3662-provision-engine-module`, cut from #104)

- **The restructure:** root `pom.xml` becomes the aggregator `io.thoryn:thoryn-cli-parent` (shared
  `${revision}`, BOM imports, Kotlin / surefire plugin config); `cli/` is the old module; `engine/` is
  `io.thoryn:thoryn-provision-engine`. **7 `target/` path references** across `ci.yml` / `release.yml`
  change; the CI commands run at the root and are unchanged (**ran:** `./mvnw -pl cli test` alone cannot
  resolve the engine — it is reactor-only, never installed — which is fine because nothing runs it that way).
- **The engine stays inside the deliverables that already ship:** the shaded `thoryn.jar` and the native
  binaries contain the engine's classes exactly as before (shade merges the reactor sibling); the three
  reflective receipt types and the schema resource moved to
  `engine/src/main/resources/META-INF/native-image/io.thoryn/thoryn-provision-engine/` and are merged the
  same way. The composite Action — the SSO-3665 consumer — needs **nothing**.
- **Publishability, measured but not wired:** a parent-free flattened POM (`flattenMode=oss`;
  **ran:** with `resolveCiFriendliesOnly` the installed POM still named `io.thoryn:thoryn-cli-parent` and a
  consumer failed with `Could not find artifact io.thoryn:thoryn-cli-parent:pom`; with `oss` every version
  is inlined) and a `distributionManagement` on `maven.pkg.github.com/thoryn-io/thoryn-cli`. **Ran:** the
  artifact installed from this branch into `~/.m2` and declared in `servers/starter-orchestrator/pom.xml`
  **compiles** oauthy's orchestrator against `ProvisionEngine` / `ProvisionFile` / `ProvisionApi`;
  `dependency:tree -Dverbose` re-manages the engine's Jackson 3.2.2 → 3.2.3 and kotlin-stdlib 2.4.10 →
  **2.3.21**, one Jackson line, no `com.fasterxml` databind. The one-job release step and the credential
  it implies (a token to READ from GitHub Packages even when public; Maven Central as the credential-free
  channel, `io.thoryn` **unclaimed** — ran: 0 artifacts on `search.maven.org`) are **deferred** with the
  consumer they would serve.
- **A runtime trap measured on the way:** oauthy's BOM imports `spring-boot-dependencies` (Kotlin
  **2.3.21**) BEFORE `kotlin-bom` (2.4.20), so first-declared-wins leaves every oauthy service on a 2.3.21
  stdlib while compiling with 2.4.20. A 2.4-only stdlib call in the engine would compile here and fail in
  such a host at runtime. The engine is therefore compiled with `languageVersion` / `apiVersion` **2.3**.
  (The ordering itself is an oauthy finding, filed separately.)

## Decision

**The engine lives in thoryn-cli as `engine/`, artifact `io.thoryn:thoryn-provision-engine`, versioned with
the CLI and shipped inside it. It is a real module with an enforced boundary (no picocli, no TTY, no CLI
type), and it is made publishable; it is NOT published until something consumes it in-process.**

Why, with the numbers:

1. **Its consumer is the CLI.** SSO-3665 made the App dispatch a job that runs this repository's Action on
   the released `thoryn.jar`. The engine has one consumer and it is in this repository; putting the code a
   repository away from its only consumer, its schema and its 11 test classes buys nothing.
2. **Release coupling runs one way, and it is the way the work flows.** 14 engine changes in five weeks,
   all from CLI Stories; ~daily `cli-v*` releases; zero `libs-v*` releases ever. In this home an engine
   change is one PR and one tag.
3. **A public repository cannot depend on a private repository's packages without breaking its own build
   for everyone outside the org** (5 `mvnw` invocations, all from-source builds, no fork PRs). Candidate 2's
   credential question only arises when something outside this repo consumes the artifact — and then it
   lands on oauthy, a private repo whose CI already holds `read:packages` tokens, with Maven Central as the
   credential-free end state.
4. **Nothing technical favours oauthy.** Both homes compile Spring-free; Jackson is the same line in both;
   the orchestrator compiles against the artifact from either.

**Why still a module, if nothing else consumes it today:** the boundary is what SSO-3659/SSO-3660 asked for
("no CLI-only types in the engine's public surface") and what makes the fallback-to-in-process cheap if
SSO-3665's dispatch model ever changes (e.g. a hub exchange for an App installation token, candidate 1 in
that ticket). An ArchUnit test keeps the boundary true while nobody is looking; a `src/` folder would not.

## Rejected alternative — oauthy `core/lib/provision`

Measured cost: a PAT on every build of a public repository (2 workflows, 5 `mvnw` invocations, all
from-source builds, no fork PRs); a two-repo, two-tag round trip for each of ~14 engine changes in five
weeks onto a shared-libs train with zero releases to date; the engine's tests and schema a repository away
from its code; and, after SSO-3665, a consumer in oauthy that does not exist. What it would have bought:
co-location with the platform's other `core/lib` modules. The spike showed co-location is not needed for
correctness (no Spring, no platform dependency; the engine's contract with product-api is the same JSON
the CLI already speaks, checked cross-repo by the staging run like the rest of `ProductApiClient`).

The two alternatives the parent ADR already rejected stand: the App does not shell out to a pinned
`thoryn.jar` as a subprocess of the orchestrator, and it does not re-implement converge. (Running the
released jar inside a dispatched job — SSO-3665 — is the Action path the parent ADR named as the fallback,
triggered by the App; the engine is the same bytes either way.)

## Consequences

- **Module layout:** `pom.xml` (aggregator) · `engine/` · `cli/`. Build and release commands run at the root
  as before; the CLI's outputs are under `cli/target/`.
- **The boundary is enforced, not described:** `ProvisionEngineLibraryBoundaryArchTest` (ArchUnit,
  `engine/src/test`) fails the build on any picocli dependency, any `java.io.Console` / `System.console()`
  / `kotlin.io.ConsoleKt` use, or any `com.devnow.thoryn.cli..` type. Each rule was watched failing against
  a deliberate violation (a `System.console()` call; a `picocli.CommandLine` reference with picocli on the
  classpath; an object in a `com.devnow.thoryn.cli` package) before it was trusted — on the main-based
  spike; the test file on #104 is byte-identical. The one blind spot (an inlined `const val` leaves no
  bytecode dependency) is written into the test; the Maven module graph (the engine declares no dependency
  on the CLI) is the primary wall.
- **The port is the engine's public contract:** `ProvisionApi`'s 38 signatures are `ProductApiClient`'s at
  extraction time. A new product-api call the engine needs is a new port method — a deliberate, visible
  change — not a reach into the CLI's client.
- **Publication is one step, when needed:** add a release job `./mvnw -pl engine -Drevision=<version>
  deploy` (`packages: write`, `GITHUB_TOKEN`) for GitHub Packages, or a Central publish once `io.thoryn` is
  claimed. The consumer's build then needs a read credential for GitHub Packages (none for Central). Until
  then, no `release.yml` change, no new secret, no artifact nobody downloads.
- **Kotlin API level 2.3** on the engine until oauthy's BOM moves its runtime stdlib; raise both together.
- **Ordering with SSO-3659:** this extraction was cut FROM #104 (`feat/sso-3659-fga-gated-ownership`) so it
  lifted the grown engine; #104 merged on 2026-10-13 (squash `684d697`) while the spike ran, and the
  extraction was rebased onto `main` — a plain move + port. SSO-3659's shapes needed no change to be
  lifted: `listMyAccess` became a port method, `PeerReceipts` stayed CLI-side as its KDoc already said.
- **Receipts stay byte-identical:** `ProvisionReceiptStore` and its mapper are unchanged.
- **For oauthy:** the orchestrator carries no dependency on the engine; SSO-3660's `ProvisionConverger`
  seam becomes the dispatcher of the SSO-3665 job rather than an in-process caller. The parent ADR §3
  gains a one-line pointer to this document.

## Amendment 1, 2026-10-13 — `PeerReceipts` is gone; the gate asks the platform per object (SSO-3673)

The "one-owner guard fed by `PeerReceipts`" described above was the interim for a platform marker that did
not exist (parent ADR Amendment 2). oauthy SSO-3667 (`844bbbbc4`; ADR
`2026-10-13-platform-owner-relation-and-forward-check.md`, parent ADR Amendment 4) shipped the marker — the
`owner` relation on `application` / `environment`, rendered as `owner: { subject }` — and the per-object
forward check `POST /api/v1/access/check`. SSO-3673 moves the engine onto both: the `ProvisionApi` port
gains `checkAccess(object, relation): AccessCheck`; `gate()` asks it per object (`manager` for a change,
`viewer` for a `readOnly` reference, `manager` on the parent for a create) and derives `access_owned_elsewhere`
from the live object's `owner` plus `check(object, owner)`; `listMyAccess` stays for `import` only. The
CLI-side `PeerReceipts` and the `--peer-receipt` flag are **removed** — nothing else consumed them, and a
hint that can refuse is an authority — so the port is the engine's whole contract with product-api again
(no second, file-shaped input), which is the shape the extraction wanted. `grants:` refuses
`relation: owner` (`ProvisionFile.GRANT_OWNER_REFUSED`); `AccessRefs.RELATIONS` gains `owner` for
`thoryn access grant | revoke | mine`. Receipts stay readable: `OwnedResource.owner` is additive.
