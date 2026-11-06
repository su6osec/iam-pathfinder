# Facts, sources and honest caveats

Every rule and design decision in `iam-pathfinder` traces back to either a
documented AWS behaviour (with a link) or an explicitly labelled approximation.
This file lists both, so you can judge how much to trust a finding.

**No claim here is invented.** If something is not documented, it is filed
under *Assumptions* below instead of being presented as fact.

## Verified facts (with sources)

### 1. The export's shape

| Fact | Source | Used for |
| --- | --- | --- |
| `GetAccountAuthorizationDetails` returns `UserDetailList`, `GroupDetailList`, `RoleDetailList` and `Policies` (arrays of `UserDetail`, `GroupDetail`, `RoleDetail`, `PolicyDetail`) | [AWS API reference: GetAccountAuthorizationDetails](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html) | `parser.parse_export` accepts exactly these top-level keys and rejects input that contains none of them |
| `UserDetail.GroupList` is *a list of IAM groups that the user is in*, type **Array of strings** | [AWS API reference: UserDetail](https://docs.aws.amazon.com/IAM/latest/APIReference/API_UserDetail.html) | group membership is resolved by **name** (`_group_names`), not by ARN |
| The AWS CLI command is `aws iam get-account-authorization-details` | [AWS CLI reference](https://awscli.amazonaws.com/v2/documentation/api/2.1.21/reference/iam/get-account-authorization-details.html) | README / walkthrough instructions |

### 2. Policy evaluation semantics

| Fact | Source | Used for |
| --- | --- | --- |
| Evaluation is a logical OR over allows, then explicit denies win: an explicit `Deny` overrides any allow | [AWS: Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) | `PermissionQuery` status ordering: deny → allow → not_allowed |
| By default a request is denied; statements are evaluated against every applicable policy | [AWS: Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html) | a principal with no matching statement gets `not_allowed` (never "allowed by default") |
| `NotAction` is valid in a statement and applies to the resources listed, excluding the listed actions | [AWS: NotAction](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html) | `NotAction` is treated as the complement of its action list on the same resources; findings derived from it are capped at **medium confidence** because the complement depends on the full AWS action list |
| `Condition` keys (and their operators) decide whether a statement applies at request time | [AWS: Conditions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html) | a statement with `Condition` still *matches* but is flagged `conditional`, reported with medium confidence and an explanatory note — never evaluated |
| Permission boundaries cap what an identity policy can grant | [AWS: Permissions boundaries](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html) | **not implemented** — listed as a limitation in the README |

### 3. Principals and trust policies

| Fact | Source | Used for |
| --- | --- | --- |
| In `Principal`, an account can be written as `arn:aws:iam::123456789012:root` **or** the shortened `"AWS": "123456789012"` — *"The account ARN and the shortened account ID behave the same way"* | [AWS: Policy elements — Principal](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html) | `TrustAccountRootRule` accepts both forms; `trust.py` classifies bare account ids and root ARNs identically |
| The `:root` suffix means *the account's principals*, not the root user | [AWS Security Blog: trust policies](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/) | `TRUST_POLICY_ACCOUNT_ROOT` is graded **low** and described as informational: any principal in the account that may assume the role can reach it |
| An account root principal in a trust policy means any principal *inside* that account that holds `sts:AssumeRole` on the role can assume it | [AWS Security Blog: trust policies](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/) | why `TRUST_POLICY_ACCOUNT_ROOT` + wildcard `sts:AssumeRole` is called out in the rule text |
| `iam:AddUserToGroup` supports the **group** resource type (required) | [AWS service authorization reference: IAM actions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_iam.html) | `IAM_ADD_USER_TO_GROUP` fires on a group ARN, `*`, and also on a user ARN (conservative: AWS documents `group`, but a `Resource: <user-arn>` statement is worth seeing rather than hiding) |

### 4. Known escalation techniques

| Fact | Source | Used for |
| --- | --- | --- |
| `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:Attach*Policy`, `iam:Put*Policy`, `iam:AddUserToGroup`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole`, `iam:PassRole` are documented privilege-escalation primitives | [Rhino Security Labs: AWS privilege escalation methods and mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) | the 12 single-permission rules and the 4 `PassRole` combination rules |
| `iam:PassRole` combined with `ec2:RunInstances`, `lambda:CreateFunction`/`InvokeFunction`, or `cloudformation:CreateStack` lets a principal attach an arbitrary role to compute it controls | [Rhino Security Labs: AWS privilege escalation methods and mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) | `PASSROLE_EC2_RUNINSTANCES`, `PASSROLE_LAMBDA_CREATE_INVOKE`, `PASSROLE_CLOUDFORMATION_CREATE_STACK` |
| Wildcard actions in policies (`*`, `?`) are supported and matched literally by the policy engine | [AWS: Policy elements — Action](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html) | `pattern_matches` compiles IAM wildcards to regular expressions; `patterns_overlap` decides whether two wildcard scopes can meet |

## Documented approximations (design decisions, not facts about AWS)

These are choices this tool makes because the export does not contain enough
information to do better. Each one is visible in the output (confidence
labels and notes), never silent.

1. **Conditions are not evaluated.** The export contains condition *statements*
   but not the request context (MFA state, source IP, tags, time). A conditional
   allow is reported as *possible*, with medium confidence and a note; a
   conditional deny is ignored entirely so it can never hide a risk.
2. **Explicit `Deny` is approximated per query.** An unconditional deny
   suppresses a finding only when it covers the same action *and* the queried
   resource. Narrower or resource-ignoring queries downgrade confidence to
   `low` and add a note instead of suppressing. This errs towards reporting.
3. **Permission boundaries are ignored.** The export carries a
   `PermissionsBoundary` field; a principal that is boundary-restricted can
   therefore appear more powerful than it is. This is a *false-positive*
   direction and is called out in the README limitations.
4. **`NotAction` complements are symbolic.** We cannot enumerate every AWS
   action, so a `NotAction` statement is treated as "everything except the
   listed actions" on the same resources and always graded medium confidence.
5. **Multi-hop depth is capped** (`--max-depth`, default 4) with cycle
   protection. Longer chains are not reported rather than reported wrongly.
6. **Escalation edges come from the rule catalogue.** The graph only contains
   `sts:AssumeRole` edges plus edges for rules in `graph.ESCALATING_RULES`; a
   technique no rule knows about will not appear as a path (it can still appear
   as a finding).

## Assumptions and unverified items

Stated plainly because they are *not* confirmed by a source:

* **`Resource` scope of `iam:AddUserToGroup`.** AWS documents `group` as the
  required resource type; the rule additionally accepts a user ARN so that an
  unusual-but-real policy is not missed. Treated as conservative, not as fact.
* **Cross-service confused-deputy chains** beyond the four modelled PassRole
  combinations are not enumerated.
* **Whether a permission is actually used** (last used, CloudTrail activity)
  cannot be known from this export; the tool reports *existence*, never
  *usage*, and never claims a permission has been exercised.
* **Numbers in the report** (finding counts, path counts, scope counts) are
  computed from the export at runtime. There are no benchmarks, scores,
  industry statistics or "risk percentages" anywhere in this project —
  including the README — because none were measured.

## What this tool deliberately does not do

* No AWS SDK, no credentials, no network calls (the only I/O is reading the
  export you point at).
* No scanning, no exploitation, no credential validation.
* No claims about real accounts: every artifact in this repository uses the
  synthetic account `123456789012`.
