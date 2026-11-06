# Architecture

How `iam-pathfinder` turns an IAM export into findings, paths and reports.

```
export.json
   │  parser.parse_export / load_export          (parser.py)
   ▼
Account {users, groups, roles, managed_policies, account_id}
   │  evaluator.build_effective_permissions      (evaluator.py)
   ▼
{principal → EffectivePermissions}  + group inheritance
   │  AnalysisContext                            (context.py)
   ▼
rules.ALL_RULES  ──check(ctx)──►  Finding[]      (rules/*.py)
   │  analyzer.run_rules                         (analyzer.py)
   ▼
normalized, sorted findings
   │  graph.build_graph / find_paths             (graph.py)
   ▼
EscalationGraph + EscalationPath[]
   │  render.Report                              (render/report.py)
   ▼
table | json | markdown | sarif | mermaid | html (render/*.py)
```

Design rule: **facts flow one way**. Renderers never re-derive anything, rules
never format anything, and only the parser talks to the file system. A
`Report` is the single object every format consumes, which is why all six
formats always describe the same analysis.

## 1. Parsing (`parser.py`)

`parse_export(data)` accepts the JSON object returned by
`aws iam get-account-authorization-details`:

| Export key | Model |
| --- | --- |
| `UserDetailList` | `User` (name, arn, `GroupList`, inline `UserPolicyList`, `AttachedManagedPolicies`) |
| `GroupDetailList` | `Group` |
| `RoleDetailList` | `Role` (`AssumeRolePolicyDocument` → `trust_policy`, inline, attached) |
| `Policies` | `ManagedPolicy` with **all** versions; `default_version` picks `IsDefaultVersion` / `DefaultVersionId` |

Details that matter:

* Policy documents arrive URL-encoded (from `GetRole`-style responses) or as
  plain dicts; both are accepted and normalised to a `PolicyDocument` of
  `Statement` objects.
* Attachments are stored as `(name, arn)` pairs and resolved against the
  account's managed policies *after* parsing. Any ARN that does not resolve is
  reported in `ParsedExport.unresolved_policy_arns` — the CLI prints it instead
  of silently under-computing permissions.
* `account_id` is derived from any ARN in the export (the tool never guesses).
* Parsing is tolerant of unknown keys and missing sections; malformed structure
  raises `ParseError`, which the CLI turns into exit code 2.

## 2. Effective permissions (`evaluator.py`)

`build_effective_permissions(account)` produces, for every user, group and
role, an `EffectivePermissions` — the list of `StatementRef`s that apply to it.
Each ref remembers where it came from (`inline`, `managed`, or *via group*) so
findings can cite `group "Developers" managed policy "DeveloperAccess"`.

A group's statements are additionally attached to each member user (this is how
`GroupList` inheritance works: `UserDetail.GroupList` is an array of group
names — see `docs/FACTS.md`).

### Permission queries

`EffectivePermissions.query(action, resource)` returns a `PermissionQuery`
whose `status` is `allowed`, `denied` or `not_allowed`, plus the supporting
`allows`, `denies` and `partial_denies` statement refs.

* **Wildcards**: `action_covers` / `resource_covers` translate IAM `*` and `?`
  patterns to regular expressions, so `iam:*` covers `iam:CreatePolicyVersion`
  and `*` covers everything. `patterns_overlap` (used where scope matters, e.g.
  PassRole pairing) checks whether two patterns can match a common value.
* **`NotAction` / `NotResource`**: treated as the complement — "everything the
  export's action list does not mention" on the same resources. Because the
  complement is only meaningful relative to the full AWS action list, findings
  derived from `NotAction` are graded **medium confidence**.
* **`Condition`**: a statement with a condition still *matches*, but the query
  is flagged `conditional`, the finding is marked conditional and given a note.
  Conditions are never evaluated: the export does not contain the context keys
  that decide them.
* **Explicit `Deny` (documented approximation)**:
  * unconditional deny covering the same action **and** resource → `denied`
    (finding suppressed);
  * unconditional deny on the same action but narrower/different resource when
    the query is resource-unaware → `partial_denies`: the finding is kept and
    confidence is lowered to **low** with a note;
  * conditional deny → ignored (it must never hide a possible finding).

`is_full_admin()` is the standing-admin test: an unconditional `Action: *` on
`Resource: *` with no unconditional deny covering it. A conditional universal
allow does **not** count.

## 3. Rules (`rules/`)

| Module | Contents |
| --- | --- |
| `base.py` | `Severity`, `Confidence`, `Evidence`, `Finding`, `Rule` |
| `escalation_single.py` | 12 single-permission escalation rules |
| `combination.py` | 4 `iam:PassRole` combination rules |
| `hygiene.py` | 7 hygiene/exposure rules |
| `helpers.py` | shared scope/confidence/evidence helpers |
| `__init__.py` | `ALL_RULES` — the only registration point |

A rule is a class with stable metadata:

```python
class ExampleRule(Rule):
    id = "EXAMPLE"                 # stable, used in output, SARIF, tests
    title = "..."                  # one line
    severity = Severity.HIGH
    category = "escalation"        # escalation | combination | hygiene
    explanation = "..."            # what it detects and why it matters
    remediation = "..."            # what to do about it
    references = [URL, ...]        # only real, cited URLs
    required_permissions = ["..."] # what the principal must hold
    principal_types = ("user", "role")

    def check(self, ctx): ...
```

`check` uses only `ctx` (effective permissions, trust helpers, principal
iteration) and returns `Finding`s via `rule.make_finding(...)`, which fills in
ARN, title, severity and remediation.

### Central policies (`analyzer.run_rules`)

Applied for every rule, so no rule has to remember them:

1. a principal that already holds full admin never receives an *escalation* or
   *combination* finding — `FULL_ADMIN` covers it instead;
2. conditional findings get an explanatory note;
3. low-confidence findings (only ever caused by a partial explicit deny) get a
   note explaining why;
4. findings are sorted by severity (desc), rule id, principal type, principal
   name — output is deterministic.

## 4. Escalation graph (`graph.py`)

* **Nodes**: one per user and per role, plus `virtual:admin`.
* **`assume` edge** `principal → role` requires *all* of:
  `sts:AssumeRole` allowed for the principal, the allow's resource scope
  covering the role ARN, and the role's trust policy admitting the principal
  (`trust_allows`, which compares against the principal ARN and account id).
* **`escalate` edge** `principal → virtual:admin` exists when a finding from
  `ESCALATING_RULES` (the 12 single-permission rules, the 4 PassRole rules,
  `FULL_ADMIN`, `SERVICE_WILDCARD`, `BROAD_NOT_ACTION`) names that principal.
* **Paths**: `find_paths` walks from every user and role to `virtual:admin`
  with a configurable depth limit (default 4) and cycle protection — a node
  already on the current path is never revisited, so mutually-trusting roles
  terminate. Results are sorted by length then description, so two runs produce
  identical output.

## 5. Rendering (`render/`)

`Report` holds the context, findings, paths, graph, filter and metadata
(computed counts only — nothing is estimated). Renderers:

| Module | Notes |
| --- | --- |
| `table.py` | fixed-width index + detail blocks; no third-party table lib |
| `jsonformat.py` | `tool`, `summary`, `findings`, `escalation_paths` |
| `markdown.py` | headings, tables, per-finding sections, path list |
| `sarif.py` | SARIF 2.1.0: all 23 rules as tool rules, findings as results, level mapped from severity, principal ARN as `logicalLocations`, stable `partialFingerprints` |
| `mermaid.py` | `graph TD`; node ids sanitised to `[A-Za-z0-9_]`; paths as `%%` comments |
| `html.py` | one file: inline CSS, no scripts, no external URLs, every export-derived value HTML-escaped |

## 6. CLI (`cli.py`)

Typer app with `analyze`, `explain`, `rules` and `--version`.

* `--format` and severity options are validated **before** any work happens.
* `ParseError`/`OSError` → `error: …` on stderr, exit **2**.
* `--fail-on SEVERITY` → exit **1** when a reported finding is at or above the
  threshold (checked after `--min-severity` filtering, so the gate reflects
  what you actually asked to see).
* `--out FILE` writes the report; a one-line confirmation goes to **stderr**
  so stdout stays machine-readable.

## 7. Testing strategy

| Layer | What is asserted |
| --- | --- |
| evaluator | wildcard/`?` matching, `NotAction`, deny approximation, conditions, group inheritance, full-admin detection |
| rules | for **every** registered rule: a vulnerable fixture that must fire and a safe fixture that must produce **zero** findings of any rule |
| graph | edge preconditions, 2-hop and 3-hop paths, depth limit, cycle termination, deterministic ordering |
| render | all six formats, cross-format consistency, SARIF envelope, HTML self-containment and escaping |
| cli | exit codes 0/1/2 for every error class, every format end to end |
| docs | README samples and `docs/RULES.md` are regenerated from real output and compared, so documentation cannot drift |

Fixtures are generated by `tests/fixtures/generate_fixtures.py` (committed as a
maintenance tool) and the example account by `examples/generate_example.py`;
both are deterministic and use only account `123456789012`.

## 8. Extension guide

1. Add a `Rule` subclass in the right module with a new stable id.
2. Register it in the module's rule tuple (and only there) — `ALL_RULES`
   picks it up automatically.
3. Run `python tests/fixtures/generate_fixtures.py` and fill in the new
   vulnerable/safe fixture pair.
4. Run `python docs/generate_rules_md.py` to refresh `docs/RULES.md`.
5. `.venv/bin/pytest -q && .venv/bin/ruff check src tests`.

The safe-fixture contract (`test_safe_fixture_produces_no_findings`) will fail
until the new fixture exists, which is exactly the point.
