# Security maintenance

The updater proposes authenticated security fixes. A separate App approves only
changes that satisfy the policy on protected `main`, fresh advisory checks and
the exact required validation runs. Native source upgrades, workflow changes and changes to approval or security rules
require human review. Signed Unbound security-source updates can be proposed
automatically, but carry an explicit human-review requirement. The public Debian
source signing key is bundled with the reviewed tooling; the source lock still
requires its previously pinned fingerprint and the separate upstream signature.

The initial rollout is report-only. Both `security/update-policy.json` and
`LANRITH_SECURITY_APPROVALS_ENABLED` must enable approval before the reviewer can
submit an approving review. The merge check remains pending until the exact
approval decision is archived immutably and independently rechecked. Proposal
inputs are also archived before a PR can be created. The policy must contain the independent reviewer's
numeric App ID. Neither App has branch-protection bypass permission.

## Owner setup

Create a private App at
[the organization's App settings](https://github.com/organizations/Lanrith/settings/apps/new)
using `.github/apps/security-reviewer.json` as the permission specification.
Disable webhooks. Grant only Actions read, Checks write, Contents read, Metadata
read and Pull requests write. Install it on `lanrith`, `discovery-bridge` and
`router-policy-agent` using **Only select repositories**. Generate and download
its private key locally; never paste a key into a PR, issue or chat.

Expand the existing `lanrith-dependency-updater` installation to the same three
repositories. Its permissions remain Contents write and Pull requests write.
Use an existing local updater key, or generate another key for that same App.

From a checkout of this change, run:

```sh
python3 scripts/setup-maintenance.py \
  --reviewer-id REVIEWER_APP_ID \
  --reviewer-key /path/to/reviewer.pem \
  --updater-key /path/to/updater.pem \
  --configure
```

The setup command authenticates each App, verifies the reviewer permissions,
creates protected-main-only environments and stores keys using secret input.
It never prints key or token material. Approval automation remains disabled.
After the implementation branches have been pushed, run the same command with
`--create-bootstrap-prs` instead of `--configure`. It creates bootstrap PRs as
the reviewer App so the owner can submit an independent human approval. Review
the bootstrap changes in all three repositories.

Bootstrap creation also uses the updater key to append a metadata-only commit
with the identical source tree. This makes the final push come from the updater
App, preserving GitHub's last-push approval rule when the owner reviews. The
non-forced reference update rejects concurrent branch changes. Both App keys are
required for this step; protection is kept in place.

Review the shared controls first, then merge and qualify the component compiler
fixes. Pin their newly attested immutable releases in the platform bootstrap PR
and rerun full platform qualification before merging it. A platform that still
selects the old vulnerable component binaries is not remediated.

Enable immutable releases before publishing through the new release workflow.
The publisher uploads all assets to a draft, publishes an immutable prerelease,
then verifies the source tag and each server-reported asset digest before
promoting it to stable. Retries accept only identical bytes and never replace
assets or repromote an already stable older release. It archives a separately
attested publication result because published immutable assets cannot be edited.

Complete a real pilot with human approval, qualification and verified immutable
publication. Then submit a human-reviewed PR setting `reviewer_app_id` and mode
`enforce` in each protected policy. After those policy PRs merge, run the setup
command with `--activate` instead of `--configure`. It requires the independent
App admission check, preserves existing required checks, requires up-to-date
validation, applies protection to administrators, and enables the repository
approval flag. The admission check enforces full qualification for build changes
and source checks for documentation-only PRs. Keep stale-review dismissal, last-push approval and up-to-date checks.
Keep default workflow permissions read-only and shared Actions PR approval off.

## Trace a change

Every candidate records its advisory or qualified-component reasons, base commit,
policy hash, trusted resolver commit and every changed input's before/after hash.
An unchanged candidate does not rewrite its open PR. The remediation issue links
the candidate, PR and audit run; opening a PR does not mean the issue is fixed.

Public upstream responses, including advisory and package metadata, are retained
in `input-evidence.tar.gz` with their origin, retrieval time and digest. Registry
authentication responses, request headers and credentials are excluded.

Each review records the PR identity, exact head/base commits, latest workflow
attempts, required jobs and rejection reasons. Approval adds the GitHub review ID,
reviewer App identity, commit and policy decision. Candidate source data and
successful or blocked decisions are archived as attested `audit-*` releases.
Release `update-record.json` binds the merged PR, commit-bound approvals and
successful validation to the released source. Publication verification binds that
record to the immutable asset digests. A component pin includes the attested
component update record, linking its original fix and approvals into the platform
release. The remediation issue closes only after publication verification has
been archived immutably. Audit release notes and PR text are indexes;
the signed asset bytes are the evidence.

For an audit bundle, download its files and `evidence.intoto.jsonl`, then verify:

```sh
gh attestation verify update-record.json --bundle evidence.intoto.jsonl \
  --repo Lanrith/lanrith --deny-self-hosted-runners
```

Also check the source/signer commits and workflow against the expected run and
reviewed tool revision. A valid signature alone does not establish a correct
policy decision. Do not infer runtime exploitability from a module-inventory
finding; release source and binary scans remain mandatory.

## Storage and failures

Large Actions artifacts are temporary job handoffs with one-day expiry. PRs keep
small scanner and qualification reports. Cleanup first publishes its attested
plan, then rechecks artifact identities and completed-run state before deletion.
It archives execution receipts too, distinguishing deleted artifacts from ones
GitHub expired in the meantime. A changed run or artifact blocks further deletion.
It excludes active runs, unknown artifact classes and durable release assets.
Cleanup skips empty inventories. Its own small audit handoffs expire after one day, so removing them does not generate another set of audit records.

Set `LANRITH_ARTIFACT_CLEANUP_ENABLED=true` after reviewing its first archived plan.

Scanner failures, unavailable advisory services, unsupported source migrations
and failed qualification block unattended approval. The resolver opens a tracked
attention issue when it cannot produce or publish a candidate. Paid AI services
are not used and workflows never raise spending limits.

The watchdog reports the latest failed assessment, proposal or release immediately
on workflow completion and checks scan freshness every six hours. It alerts at
18 hours, before production evidence expires at 24 hours. Recovery requires a
healthy assessment and attested publication evidence for the stable immutable
release; opening or merging a PR does not close the alert.

Retained assessment always includes the latest stable release. A passing newer
release can explicitly supersede vulnerable older ones; their signed assessments
keep `result=fail`, their retirement reason and replacement version. An unsafe
latest release cannot retire itself. Incomplete scanner coverage remains blocking.
