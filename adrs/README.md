# thoryn-cli's ADR moved to thoryn-architecture

Every Thoryn architecture decision record lives in
[thoryn-io/thoryn-architecture `adrs/`](https://github.com/thoryn-io/thoryn-architecture/tree/main/adrs)
since 2026-11-19 (oathy ADR `2026-11-18-adrs-move-to-thoryn-architecture`, epic SSO-4101, story SSO-4382).
Id, file name, decision text and git history moved unchanged.

This repository's one ADR, `2026-10-13-provision-engine-shared-library` (the provisioning engine is the
`engine/` library module of thoryn-cli), records `repo: thoryn-cli` there, so its ref stays
`thoryn-cli:2026-10-13-provision-engine-shared-library`, and a link to
`github.com/thoryn-io/thoryn-cli/blob/main/adrs/<id>.md` is found again under the same `<id>` there.

How this repository refers to a decision: prose and comments write ADR `<id>` (oathy ADR `<id>` for one of
oathy's), never a path. A link points at `https://github.com/thoryn-io/thoryn-architecture/blob/main/adrs/<id>.md`.
A new decision is written there, with `repo: thoryn-cli`, and lands first; the change here names its id.
From a thoryn-architecture checkout, `bin/arch brief --repo thoryn-cli=<this checkout> <paths>` lists the
decisions that govern the paths you change.
