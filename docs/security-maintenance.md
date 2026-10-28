# Security maintenance

The updater proposes authenticated security fixes. A separate App approves only
changes that satisfy the policy on protected `main`, fresh advisory checks and
the exact required validation runs. With `automatic_minor_security_updates: true`,
an authenticated security fix may advance an existing Go or npm dependency within
the same major version. Go updates also include only the minimum versions required
by the fixed module's checksum-verified constraints. The reviewer independently
resolves that selection from the original manifest, checks the existing module
paths and roles, and verifies changed checksums against the Go checksum database.
npm changes need exact advisory reasons, registry integrity and unchanged package
coverage. Supported Node LTS majors can receive official minor security releases.
Every automatic update still needs fresh advisory evidence, the complete required
CI, independent App approval and immutable decision evidence.

Native source upgrades, compiler support-branch migrations, workflow changes and
changes to approval or security rules require human review. Adding dependencies,
changing module roles, major migrations, prereleases, installation hooks or scripts
remain outside automatic approval. If a safe proposal cannot be formed, its
attention issue is assigned to `mikenorgate`. Policies without the minor-update
opt-in retain the previous patch-only behavior until their reviewed rollout.

Ready PRs that need human input request review from `mikenorgate` through GitHub's
review-request API only after all required CI workflows and build jobs pass for
the current head and protected base. Missing, running, failed, cancelled, skipped,
stale or mismatched builds defer the request. PR events and build starts/completions
recheck readiness; the last successful build can release the request without
another push. New heads and reruns withdraw outstanding requests until CI passes
again. Current-head reviews and pending requests are not repeated. Drafts wait
until ready. If the owner authored the
PR and cannot review it, assignment records the need for another independent
reviewer. Blocked proposal and freshness issues also receive an owner assignment.

The PR event job only signals its GitHub-controlled head with no checkout or write
permissions. A separate notification job executes the trusted protected-main
workflow source. It reads build status and can request reviews and assign issues, but has no App keys,
release-writing or signing permissions. Notification routing never approves a
change; the independent reviewer still validates the actual candidate. GitHub's
review-request timeline and the archived admission decision retain the request
and the actual review identity.

Signed Unbound security-source updates can be proposed
automatically, but carry an explicit human-review requirement. The public Debian
source signing key is bundled with the reviewed tooling; the source lock still
requires its previously pinned fingerprint and the separate upstream signature.

The initial rollout is report-only. Both `security/update-policy.json` and
`LANRITH_SECURITY_APPROVALS_ENABLED` must enable approval before the reviewer can
submit an approving review. The merge check remains pending until the exact
approval decision is archived immutably and independently rechecked. Proposal
inputs are also archived before a PR can be created. The policy must contain the independent reviewer's
numeric App ID. Neither App has branch-protection bypass permission.

`Security update admission` waits while a required workflow has not started or
is queued or running. Its details link opens the prerequisite run, and the
archived decision records that run's identity and status. Completion triggers
another admission review, which finishes the waiting check. A failed,
cancelled, skipped or stale validation still fails admission. Pending validation
cannot grant an automated approval or permit a merge.

## Owner setup

Create a private App at
[the organization's App settings](https://github.com/organizations/Lanrith/settings/apps/new)
using `.github/apps/security-reviewer.json` as the permission specification.
Disable webhooks. Grant only Actions read, Checks write, Contents write, Metadata
read and Pull requests write. Install it on `lanrith`, `discovery-bridge` and
`router-policy-agent` using **Only select repositories**. Generate and download
its private key locally; never paste a key into a PR, issue or chat.

GitHub counts required approvals only from reviewers with repository write
access. The App therefore needs Contents write on its registration and accepted
installation permissions. A Contents-read App can submit an `APPROVED` review
that does not satisfy protection, including the last-push approval rule. When
updating an existing App, save the permission change and accept it on the
installation. Keep the three selected repositories and existing branch rules.

Review jobs still request only Contents read for their short-lived installation
tokens. They execute the reviewed workflow source from protected `main` and do
not push source changes. GitHub's `authorCanPushToRepository` field verifies the
exact approving review's write authority before its decision is archived, and
again before admission succeeds. Missing authority, changed review identity or
a GraphQL error keeps the merge gate closed. The signed decision records this
authority check alongside the actual review ID and commit.

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

Merge the platform reviewer and enforcement-policy change first, with the
repository approval flag still `false`. Verify its immutable `main` release
before pinning the component workflows to that commit. Merge both component
enforcement policies and verify all three repositories before activation. This
keeps automatic approvals disabled while the repositories adopt the reviewed
implementation. Activation binds each admission check to the reviewer App and
applies branch protection to administrators.

The Debian gate maps versioned signed kernel packages to the `linux` advisory
source. Assembly requires matching `Built-Using` metadata for those payloads.
Retained assessments read the authenticated kernel package version from existing
signed source maps. Missing kernel feed data, ambiguous fields or conflicting
source metadata fail the check.

## Trace a change

Every candidate records its advisory or qualified-component reasons, base commit,
policy hash, trusted resolver commit and every changed input's before/after hash.
An unchanged candidate does not rewrite its open PR. The remediation issue links
the candidate, PR and audit run; opening a PR does not mean the issue is fixed.

Advisory reasons hash canonical JSON so upstream object key ordering cannot
invalidate an unchanged finding. Any advisory content change still requires a
fresh candidate. Public upstream responses, including advisory and package metadata, are retained
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

Before publication, a human approval must match the exact PR head and come from
an independent account with current write or admin access to the repository.
The publisher checks effective repository permissions directly because private
organisation membership can be hidden from an installation token.

For an audit bundle, download its files and `evidence.intoto.jsonl`, then verify:

```sh
gh attestation verify update-record.json --bundle evidence.intoto.jsonl \
  --repo Lanrith/lanrith --deny-self-hosted-runners
```

Also check the source/signer commits and workflow against the expected run and
reviewed tool revision. A valid signature alone does not establish a correct
policy decision. Do not infer runtime exploitability from a module-inventory
finding; release source and binary scans remain mandatory.

Each retained assessment release contains `security-assessment.json`,
`security-assessment.json.intoto.jsonl` and `diagnostics.tar.gz`. The signed report
binds the archive's size and SHA-256 in `diagnostic_archive`; its `diagnostics` map records each raw
file's hash. The archive preserves empty stdout and stderr files, which can fail
as individual release uploads. The publisher verifies every member before upload,
then checks immutability and the three server-reported asset digests. Verify the
report's provenance and archive hash before reading the diagnostics.

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

Qualification artifacts contain the flat public JSON and text reports in the output
directory. Workflow checks enforce that boundary, keeping collection independent
of the private VM and storage work directories and their access permissions.
