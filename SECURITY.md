# Security policy

## Reporting a vulnerability

Please report security issues in `iam-pathfinder` privately:

* open a GitHub security advisory on this repository
  (**Security → Report a vulnerability**), or
* email the maintainer listed in the repository's `pyproject.toml` / profile.

Please include the version (`iam-pathfinder --version`), the command you ran,
and a **redacted** reproduction (synthetic export preferred — never attach a
real account export, even a "harmless" one). You should get a response within a
few days. Fixes will be credited in the release notes if you want to be named.

## Sensitive data

An IAM authorization-details export is one of the most sensitive artifacts an
AWS account produces: it lists every principal, every policy document and every
trust relationship. That has consequences for this project:

* **The repository contains only synthetic data.** Every export, fixture and
  example in this repo uses account `123456789012` and fake names. No real
  account data is committed, in any branch or history.
* **`.gitignore` blocks the common export file names** (`export.json`,
  `get-account-authorization-details*.json`, `*.export.json`, …) so an accidental
  `git add .` cannot commit one. If you must commit an export for a test, rename
  it and make sure it is synthetic.
* **Reports inherit the sensitivity of the export.** Findings include policy
  statements, principal names and ARNs. Store reports like the export:
  encrypted at rest, access-controlled, never pasted into public issues or chat.
* **The tool reads one file and writes one file.** It does not upload,
  transmit, cache or log your data anywhere.

## Threat model (what this tool does and does not protect against)

**It does:**

* analyse an export **without network access**, so running it cannot leak data
  by itself — the only way data leaves is a report file you create;
* avoid evaluating conditions or trusting deny statements in ways that could
  *hide* a real risk: conditional denies are ignored, narrowing denies lower
  confidence instead of suppressing findings;
* escape all export-derived text in the HTML renderer (`html.escape`) and
  sanitise Mermaid node ids, so a hostile policy name cannot inject markup or
  break out of the diagram;
* treat malformed input as a controlled error (exit code 2), not a crash.

**It does not:**

* validate that an export is authentic — a tampered export yields a tampered
  report;
* evaluate service control policies, resource control policies, permission
  boundaries, AWS Organizations, or any data outside the export (see
  [docs/FACTS.md](docs/FACTS.md));
* detect whether a permission has actually been used or abused — it reports
  what is *possible*, not what happened;
* replace a human review or an AWS-side scanner.

**Report a security issue if** you find a way to make the HTML/SARIF/Markdown
renderers execute or load external content, to crash the CLI on adversarial
input instead of exiting with code 2, or to make a rule silently skip a
principal that should be reported.
