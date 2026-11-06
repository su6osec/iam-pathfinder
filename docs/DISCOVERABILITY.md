# Online Discoverability, Community Outreach & SEO Guide

This guide details concrete, high-leverage steps to maximize the discoverability, organic search ranking (SEO), and community adoption of **iam-pathfinder** across GitHub, search engines, and the cloud security community.

---

## 1. Automated Repository Enhancements (Completed)

- [x] **20 High-Intent GitHub Topics Configured:**
  Configured tags directly matching user search intent in cloud pentesting, DevSecOps, and IAM auditing:
  `aws`, `iam`, `privilege-escalation`, `cloud-security`, `aws-iam`, `aws-security`, `iam-security`, `cloudsec`, `penetration-testing`, `security-tools`, `least-privilege`, `iam-policy`, `devsecops`, `static-analysis`, `aws-pentesting`, `vulnerability-scanner`, `infosec`, `python`, `pypi`, `access-control`.
- [x] **Search-Engine Optimized Repository Description & Metadata:**
  Summary accurately captures key search terms: *offline*, *AWS IAM privilege escalation*, *risky permissions*, *authorization details*, and *zero network calls*.
- [x] **Pre-built Wheel & Sdist Release (`v0.1.0`):**
  Packaged release distributions (`iam_pathfinder-0.1.0-py3-none-any.whl` and `.tar.gz`) attached to the official GitHub Release for direct installation and indexation.
- [x] **Multi-Format Integration (SARIF & Mermaid):**
  Supports native GitHub Code Scanning SARIF ingest and GitHub Markdown Mermaid diagram rendering, expanding utility into CI/CD pipelines.

---

## 2. High-Impact GitHub "Awesome" Lists to Submit

GitHub Awesome lists rank near the top of organic search results for security queries. Submitting a Pull Request to these curated lists creates permanent backlinks and developer referrals:

1. **`my-arsenal-of-aws-security-tools`**
   - **Repository:** [toniblyx/my-arsenal-of-aws-security-tools](https://github.com/toniblyx/my-arsenal-of-aws-security-tools)
   - **Category:** *IAM / Permissions / Least Privilege*
   - **PR Entry:**
     ```markdown
     * [iam-pathfinder](https://github.com/su6osec/iam-pathfinder) - Offline AWS IAM privilege-escalation analyzer and pathfinder (zero AWS API calls, evaluates 23 escalation & hygiene rules, outputs SARIF, Mermaid, JSON, HTML).
     ```

2. **`awesome-aws-security`**
   - **Repository:** [jckuester/awesome-aws-security](https://github.com/jckuester/awesome-aws-security)
   - **Category:** *Identity & Access Management (IAM)*
   - **PR Entry:**
     ```markdown
     * [iam-pathfinder](https://github.com/su6osec/iam-pathfinder) - Offline AWS IAM privilege-escalation analyzer and multi-hop path finder with SARIF and Mermaid graph exports.
     ```

3. **`awesome-cloud-security`**
   - **Repository:** [anaynayak/awesome-cloud-security](https://github.com/anaynayak/awesome-cloud-security)
   - **Category:** *AWS Security / Auditing*

4. **`awesome-threat-intelligence` / `awesome-sec-tools`**
   - **Repository:** [sbilly/awesome-security](https://github.com/sbilly/awesome-security)

---

## 3. High-Leverage Security Newsletters & Community Outreach

Security newsletters feature new tools every week and are read by thousands of Cloud Security Architects and AppSec engineers:

1. **tl;dr sec by Clint Gibler**
   - **Website / Submission:** [tldrsec.com](https://tldrsec.com/)
   - **Angle:** Zero-network offline static analysis for IAM authorization-details exports with multi-hop privilege escalation graph analysis and SARIF export for CI.
2. **Cloud Security Reading List by Marco Lancini**
   - **Website:** [cloudsecurityreadinglist.com](https://cloudsecurityreadinglist.com/)
3. **AWS Security Digest**
   - **Website:** Curated weekly AWS security updates.
4. **Reddit (`r/aws`, `r/netsec`, `r/cloudsecurity`)**
   - **Post Title:**
     > *iam-pathfinder: Offline AWS IAM privilege escalation analyzer and path finder (Zero API calls, SARIF + Mermaid support)*
   - **Sample Reddit Post Template:**
     ```text
     Hey r/cloudsecurity,

     I open-sourced iam-pathfinder, a static analysis tool for AWS IAM privilege escalation paths and risky permissions that runs 100% offline.

     Why I built it:
     Auditing IAM usually either requires live AWS API permissions (which security teams don't always grant) or produces overwhelming unstructured policy dumps.

     What iam-pathfinder does:
     - Takes a standard `aws iam get-account-authorization-details` JSON file and requires ZERO AWS credentials or network calls.
     - Detects 23 documented escalation rules (12 single-permission escalation vectors based on Rhino Security Labs research, 4 iam:PassRole combos, 7 hygiene rules).
     - Builds an escalation graph modeling sts:AssumeRole hops and paths to admin with cycle detection and depth control.
     - Explains findings with rule remediation guides (`iam-pathfinder explain <RULE_ID>`).
     - Outputs in 6 formats: table, JSON, Markdown, HTML, Mermaid diagrams (renders directly on GitHub), and SARIF (ingests into GitHub Code Scanning).

     Repo: https://github.com/su6osec/iam-pathfinder
     Pre-built release & docs: https://github.com/su6osec/iam-pathfinder/releases

     Feedback, rule suggestions, and issues are very welcome!
     ```

---

## 4. Technical Comparison vs Existing Tools

Understanding the distinction helps users identify when to choose `iam-pathfinder`:

| Feature | `iam-pathfinder` | PMapper | CloudSplaining | Policy Sentry |
| :--- | :--- | :--- | :--- | :--- |
| **Network & AWS API Calls** | **Zero (100% Offline)** | Requires live AWS API / Graph DB | Offline (JSON export) | Offline generator |
| **Focus** | **Privilege Escalation & Paths** | Multi-hop Graph Traversal | Risk violation triaging | Least-privilege policy generation |
| **Multi-hop Graph** | Yes (AssumeRole + direct escalation) | Yes (Graph DB / Neo4j) | No | No |
| **Output Formats** | **6 (Table, JSON, MD, SARIF, Mermaid, HTML)** | CLI / Dot format | HTML report | JSON / YAML |
| **GitHub Native** | **Native SARIF + Mermaid** | No | No | No |
| **Rule Explainability** | Built-in CLI `explain <RULE>` with docs | Wiki | Rule documentation | Action database |
| **Zero Heavy Dependencies** | Pure Python standard library + minimal deps | NetworkX / Neo4j / Boto3 | Boto3 / Jinja2 / Schema | Boto3 |

---

## 5. Technical Blog Post / Case Study Guide

Publishing a technical breakdown on platforms like Medium, Hashnode, Dev.to, or LinkedIn significantly drives organic SEO:

- **Article Title:** *"Hunting Multi-Hop AWS IAM Privilege Escalation Paths Without AWS Credentials"*
- **Key Sections to Include:**
  1. The danger of shadow admin paths through chained `sts:AssumeRole` trusts.
  2. The mechanics of `iam:PassRole` vectors (EC2, Lambda, CloudFormation).
  3. Running `iam-pathfinder` on an offline account export and rendering Mermaid graphs in GitHub issues.
  4. Integrating SARIF results into GitHub Actions code scanning.
  5. Remediation strategies: separating service roles and removing wildcard trust policies.
