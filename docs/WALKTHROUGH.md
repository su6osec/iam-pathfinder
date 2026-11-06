# Walkthrough

A guided tour using the synthetic account that ships with the repository. No AWS
account is required for steps 1–3; step 0 shows how to produce a real export.

## 0. Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e .
iam-pathfinder --version        # iam-pathfinder 0.1.0
```

## 1. Get an export (real accounts only)

```bash
aws iam get-account-authorization-details --output json > export.json
```

The command needs permissions to read IAM (typically `iam:GetAccountAuthorizationDetails`
and list APIs). It returns users, groups, roles and policies **with their
documents** — which is exactly what this tool needs, and exactly why the file is
sensitive.

For the rest of this walkthrough we use the bundled example instead:

```bash
cp examples/vulnerable-account.json export.json   # optional
```

## 2. First analysis

```bash
iam-pathfinder analyze examples/vulnerable-account.json
```

Reading the header:

```text
 Scope:    6 users, 4 groups, 5 roles, 4 managed policies
 Findings: 27 (1 critical, 17 high, 8 medium, 1 low)
 Escalation paths: 19 paths (longest 2 hops)
```

* **Scope** counts come straight from the export — if the export has no roles,
  you see `0 roles`, never an estimate.
* **Findings** are grouped by rule; the index table below the header gives you
  severity, rule id, principal and title in one line each.
* **Escalation paths** are chains that end in full administrative control.

Then the `DETAILS` section shows, per finding: confidence (high/medium/low),
the required permissions, what it means, the exact policy statement that
triggered it, the remediation, and any notes (conditional, partial deny,
scope).

## 3. Follow one escalation path

In the example, `user:alice` is a devops engineer whose inline policy grants
`iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, … and `sts:AssumeRole` on
`AdminRole`, and `AdminRole` trusts alice and has `AdministratorAccess`:

```text
  19. [2 hops] user:alice
       --assume--> role:AdminRole
            alice can sts:AssumeRole AdminRole (trust policy accepts arn:aws:iam::123456789012:user/alice)
       --escalate (FULL_ADMIN)--> virtual:admin
            Principal has full administrator access (Action: * on Resource: *) (managed policy "AdministratorAccess")
```

Interpretation: alice does not hold admin *today*, but two documented steps get
her there. Fix either hop — remove `sts:AssumeRole` on `AdminRole`, or stop
trusting alice in that role's trust policy — and the path disappears.

## 4. Learn about a rule

```bash
iam-pathfinder explain PASSROLE_LAMBDA_CREATE_INVOKE
```

prints the rule's severity, category, principal types, required permissions,
the full explanation, the remediation and the references it is based on.

```bash
iam-pathfinder rules                  # the whole catalogue as a table
iam-pathfinder rules --format json    # machine-readable (23 rules)
```

## 5. Choose an output format

```bash
iam-pathfinder analyze export.json --format json      # pipelines
iam-pathfinder analyze export.json --format markdown  # PR comments
iam-pathfinder analyze export.json --format sarif     # code scanning upload
iam-pathfinder analyze export.json --format mermaid   # graph TD diagram
iam-pathfinder analyze export.json --format html      # self-contained report
iam-pathfinder analyze export.json --out report.html  # same, to a file
```

Mermaid output can be pasted straight into a Markdown file:

````markdown
```mermaid
graph TD
    ...
```
````

The HTML report embeds its CSS and never loads anything from the network, so it
can be archived or emailed as a single file.

## 6. Filter and gate

```bash
# only show critical/high
iam-pathfinder analyze export.json --min-severity high

# fail the pipeline if anything critical/high is reported (exit code 1)
iam-pathfinder analyze export.json --format json --fail-on high --out report.json
echo $?    # 1 -> gate failed
```

Exit codes: `0` success, `1` `--fail-on` reached, `2` usage/parse error
(missing file, malformed JSON, unknown format or rule id).

Note that `--fail-on` is evaluated **after** `--min-severity`, so the gate
matches exactly what you asked to see.

## 7. Interpret confidence

| Confidence | Meaning | What to do |
| --- | --- | --- |
| `high` | Unconditional allow, no narrowing deny. | Treat as real. |
| `medium` | The statement has a `Condition`, or it uses `NotAction`. | Verify manually: conditions may or may not hold in your environment. |
| `low` | A narrower explicit `Deny` matches the same action, so usable scope is uncertain. | Read the deny before deciding. |

Every conditional or low-confidence finding carries a note explaining which of
these applies — you never have to guess why a confidence was lowered.

## 8. Verify the tool yourself

```bash
.venv/bin/pytest -q                       # full suite
.venv/bin/ruff check src tests examples docs   # lint
```

Useful checks if you change anything:

* `tests/test_rules_fixtures.py` — every rule must fire on its vulnerable
  fixture and **not** fire anywhere on its safe fixture.
* `tests/test_docs.py` — the README sample blocks and `docs/RULES.md` must
  match real output, so documentation cannot drift.
* `tests/test_example.py` — the bundled example must still trigger all 23
  rules.

Regenerate the synthetic artifacts when you change them:

```bash
python tests/fixtures/generate_fixtures.py   # 46 fixture files
python examples/generate_example.py          # examples/vulnerable-account.json
python docs/generate_rules_md.py             # docs/RULES.md
```
