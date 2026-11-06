# iam-pathfinder

**Offline AWS IAM privilege-escalation and risky-permission analyzer.**
It reads one local JSON file — the output of `aws iam get-account-authorization-details` —
and reports the permissions that let a principal escalate, the roles that trust the
wrong principals, and the hygiene problems that turn a small mistake into an
account takeover. Every finding comes with an explanation, the policy statement
behind it, and concrete remediation.

> **Sensitive data warning.** An IAM authorization-details export is a map of
> everything that can be done in your account. This tool, its reports, and any
> logs you keep from it must be treated with the same care as the export itself:
> store them encrypted, do not commit them, and do not paste them into issues or
> chat. The repository only ever contains synthetic data for account
> `123456789012`.

> **No AWS calls, ever.** `iam-pathfinder` does not import an AWS SDK, does not
> read credentials, and does not open network connections. It analyses the file
> you give it. The README, docs and tests all make the same claim: everything
> reported is derived from the export, nothing is fetched.

## What it does

* **Parses the export** — users (with group inheritance), groups, roles, managed
  policies (default version), inline policies, trust policies, attached-policy
  references, `Action`/`NotAction`, `Resource`/`NotResource`, wildcards (`*`, `?`)
  and `Condition` blocks.
* **Evaluates effective permissions** per principal and answers questions like
  "may this user call `iam:CreatePolicyVersion` on this policy ARN?" with the
  supporting statement as evidence.
* **Detects 23 rules** in three families:
  * **12 single-permission escalation rules** (`IAM_CREATE_POLICY_VERSION`,
    `IAM_ADD_USER_TO_GROUP`, `IAM_CREATE_ACCESS_KEY`, …),
  * **4 `iam:PassRole` combination rules** (EC2 `RunInstances`, Lambda
    `CreateFunction`, CloudFormation `CreateStack`, plus the wildcard case),
  * **7 hygiene/exposure rules** (`FULL_ADMIN`, `SERVICE_WILDCARD`,
    `BROAD_NOT_ACTION`, `STS_ASSUMEROLE_WILDCARD` and the three trust-policy
    rules).
* **Builds an escalation graph** of `sts:AssumeRole` edges and escalation edges,
  and reports multi-hop paths such as
  `user:alice → assume role:AdminRole → virtual:admin`.
* **Explains everything**: `explain RULE_ID` prints what a rule detects, why it
  matters, the remediation and real references.
* **Renders six formats**: `table`, `json`, `markdown`, `sarif`, `mermaid`, `html`.

The full catalogue with explanations and remediations lives in
[`docs/RULES.md`](docs/RULES.md).

## Installation

Python 3.10+.

```bash
git clone <this-repo>
cd iam-pathfinder
python -m venv .venv && . .venv/bin/activate
pip install -e .          # adds the `iam-pathfinder` command
```

Development extras: `pip install -e ".[dev]"` (pytest + ruff).

## Quick start

### 1. Export the account (needs AWS credentials; run this wherever you normally run AWS CLI)

```bash
aws iam get-account-authorization-details \
  --output json > export.json
```

> The export can contain user names, policy documents and ARNs. Treat
> `export.json` as sensitive: `.gitignore` in this repository blocks the common
> export file names so it cannot be committed by accident.

### 2. Analyze it

```bash
iam-pathfinder analyze export.json
```

### 3. Look at the bundled example

The repository ships a fully synthetic account (`123456789012`) that triggers
**all 23 rules**, including a two-hop escalation path. Its output below is a real
run, captured verbatim:

```console
$ iam-pathfinder analyze examples/vulnerable-account.json
<!-- BEGIN SAMPLE:head -->
================================================================================================
 iam-pathfinder 0.1.0 - offline IAM analysis (no AWS API calls)
================================================================================================
 Export:   examples/vulnerable-account.json
 Account:  123456789012
 Scope:    6 users, 4 groups, 5 roles, 4 managed policies
 Findings: 27 (1 critical, 17 high, 8 medium, 1 low)
 Filter:   min-severity=low
 Escalation paths: 19 paths (longest 2 hops)

SEVERITY   RULE                           PRINCIPAL                TITLE
------------------------------------------------------------------------------------------------
CRITICAL   FULL_ADMIN                     user bob                 Principal has full administrator access (Action: * on Resource: *)
HIGH       BROAD_NOT_ACTION               group Auditors           Allow with NotAction grants broad access
HIGH       FULL_ADMIN                     group Admins             Principal has full administrator access (Action: * on Resource: *)
HIGH       FULL_ADMIN                     role AdminRole           Principal has full administrator access (Action: * on Resource: *)
HIGH       IAM_ADD_USER_TO_GROUP          user dave                Add a user to an IAM group
HIGH       IAM_ATTACH_GROUP_POLICY        user alice               Attach a managed policy to an IAM group
HIGH       IAM_ATTACH_ROLE_POLICY         user alice               Attach a managed policy to an IAM role
HIGH       IAM_ATTACH_USER_POLICY         user alice               Attach a managed policy to an IAM user
HIGH       IAM_CREATE_ACCESS_KEY          user dave                Create access keys for other IAM users
HIGH       IAM_CREATE_POLICY_VERSION      user alice               Create a new version of an IAM policy the principal can modify
HIGH       IAM_LOGIN_PROFILE              user dave                Create or reset console passwords for other IAM users
HIGH       IAM_PUT_GROUP_POLICY           user alice               Write an inline policy onto an IAM group
HIGH       IAM_PUT_ROLE_POLICY            user alice               Write an inline policy onto an IAM role
HIGH       IAM_PUT_USER_POLICY            user erin                Write an inline policy onto an IAM user
HIGH       IAM_SET_DEFAULT_POLICY_VERSION user alice               Activate a different version of an IAM policy
HIGH       IAM_UPDATE_ASSUME_ROLE_POLICY  user alice               Rewrite a role's trust policy, then assume the role
HIGH       SERVICE_WILDCARD               group SecurityTeam       Service-wide wildcard permission (e.g. iam:*)
HIGH       TRUST_POLICY_PUBLIC            role LambdaExecRole      Role trust policy allows any principal (*)
MEDIUM     PASSROLE_CLOUDFORMATION_CREATE_STACK user carol               Pass a role to a new CloudFormation stack
MEDIUM     PASSROLE_EC2_RUNINSTANCES      user carol               Pass a role to a new EC2 instance (instance profile)
MEDIUM     PASSROLE_LAMBDA_CREATE_INVOKE  user carol               Pass a role to a new Lambda function, then invoke it
MEDIUM     PASSROLE_WILDCARD              user frank               iam:PassRole with Resource: *
MEDIUM     STS_ASSUMEROLE_WILDCARD        group Admins             sts:AssumeRole with Resource: *
MEDIUM     STS_ASSUMEROLE_WILDCARD        role AdminRole           sts:AssumeRole with Resource: *
MEDIUM     STS_ASSUMEROLE_WILDCARD        user bob                 sts:AssumeRole with Resource: *
MEDIUM     TRUST_POLICY_CROSS_ACCOUNT     role LegacyCrossAccount  Role trusts an external AWS account without sts:ExternalId
LOW        TRUST_POLICY_ACCOUNT_ROOT      role ReportingRole       Role trusts the account root (informational)
<!-- END SAMPLE:head -->
```

The escalation-path section of the same run:

```text
<!-- BEGIN SAMPLE:path -->
  19. [2 hops] user:alice
       --assume--> role:AdminRole
            alice can sts:AssumeRole AdminRole (trust policy accepts arn:aws:iam::123456789012:user/alice)
       --escalate (FULL_ADMIN)--> virtual:admin
            Principal has full administrator access (Action: * on Resource: *) (managed policy "AdministratorAccess")
<!-- END SAMPLE:path -->
```

Regenerate the example at any time with `python examples/generate_example.py`.

## Commands

| Command | Purpose |
| --- | --- |
| `iam-pathfinder analyze EXPORT` | Run every rule over an export and render a report. |
| `iam-pathfinder explain RULE_ID` | Full documentation of one rule (case-insensitive id). |
| `iam-pathfinder rules` | List the whole catalogue (`--format json` for machines). |
| `iam-pathfinder --version` | Print the version. |

### `analyze` options

| Option | Default | Meaning |
| --- | --- | --- |
| `--format`, `-f` | `table` | `table`, `json`, `markdown`, `sarif`, `mermaid`, `html`. |
| `--min-severity` | `low` | Hide findings below `low`/`medium`/`high`/`critical`. |
| `--fail-on` | off | Exit `1` if any *reported* finding is at or above this severity. |
| `--out`, `-o` | stdout | Write the report to a file (`wrote <path>` on stderr). |
| `--max-depth` | `4` | Maximum number of hops in a reported escalation path. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed (and no `--fail-on` threshold was reached). |
| `1` | `--fail-on` threshold reached — intended for CI gates. |
| `2` | Usage error: missing/invalid file, malformed JSON, unknown format or rule. |

### CI gate example

```bash
iam-pathfinder analyze export.json --format json --fail-on high --out report.json
```

### Output formats

| Format | Use it for |
| --- | --- |
| `table` | Terminals and CI logs: fixed-width index plus per-finding detail. |
| `json` | Pipelines: `tool`, `summary`, `findings`, `escalation_paths`. |
| `markdown` | PR comments and internal docs. |
| `sarif` | GitHub code scanning upload (`sarif` 2.1.0, all 23 rules as tool rules). |
| `mermaid` | Pasting a `graph TD` escalation diagram into any Markdown file. |
| `html` | Sharing a report: one self-contained file, inline CSS only, no scripts, no external requests. |

All formats are produced from one report object, so they always describe the
same analysis — only the packaging differs.

## Example account

`examples/vulnerable-account.json` is synthetic and intentionally over-permissive:
6 users, 4 groups, 5 roles, 4 managed policies, 27 findings and 19 escalation
paths (18 one-hop, 1 two-hop). It exists so you can see every rule fire without
touching a real account:

```bash
iam-pathfinder analyze examples/vulnerable-account.json --format markdown
iam-pathfinder analyze examples/vulnerable-account.json --format mermaid
iam-pathfinder explain PASSROLE_LAMBDA_CREATE_INVOKE
```

## How it works (short version)

1. **Parse** the export into users, groups, roles, policies and statements.
2. **Evaluate** each principal's effective statements — including statements
   inherited from groups — into `PermissionQuery` answers (allowed / denied /
   not allowed) with `Condition` and explicit-`Deny` caveats attached.
3. **Run** the 23 registered rules against that context.
4. **Build** the escalation graph (`assume` edges require both the permission and
   a trust policy that accepts the principal) and walk it to `virtual:admin`
   with a depth limit and cycle protection.
5. **Render** one immutable report in the requested format.

Details, including the deliberate approximations, are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md); verified facts and their sources
are in [`docs/FACTS.md`](docs/FACTS.md); a guided tour is in
[`docs/WALKTHROUGH.md`](docs/WALKTHROUGH.md).

## Known limitations

Honest list — these are design decisions, not bugs:

* **Conditions are not evaluated.** A statement with a `Condition` is reported
  as *conditional* with medium confidence and a note; its actual effect depends
  on context keys the export does not contain.
* **Permission boundaries are not applied.** The export carries a
  `PermissionsBoundary` field; effective permissions here are computed from
  policies only, so a boundary-restricted principal may look more powerful than
  it is.
* **Explicit `Deny` is approximated.** An unconditional deny suppresses a finding
  only when it covers the same action *and* resource; narrower denies lower
  confidence instead of hiding the finding, and conditional denies are ignored
  (they must never hide a risk).
* **Service control policies, resource control policies, SCPs/RCPs, RAM shares
  and AWS Organizations structure are out of scope** — none of them appear in
  this export type.
* **NotAction is treated as "everything except"** the listed actions on the
  same resources; findings from `NotAction` statements are graded medium
  confidence.
* **Multi-hop paths are bounded** by `--max-depth` (default 4) and only model
  `sts:AssumeRole` and direct escalation capabilities — no cross-service
  confused-deputy chains beyond the four PassRole rules.
* **No credential or live-data checks**: the tool cannot tell you whether a
  permission is *used*, only whether it exists.

## Development

```bash
.venv/bin/pytest -q                  # test suite
.venv/bin/ruff check src tests examples docs   # lint
python examples/generate_example.py   # regenerate the example export
python docs/generate_rules_md.py      # regenerate docs/RULES.md
```

CI runs ruff and pytest on every push (`.github/workflows/ci.yml`).
Tests cover the evaluator (wildcards, `NotAction`, deny approximation,
conditions, group inheritance), every rule with a vulnerable *and* a safe
fixture, the escalation graph, all six renderers, the CLI's exit codes, and the
documentation samples (so the snippets in this README cannot drift from real
output).

## License

MIT — see [LICENSE](LICENSE).
