# Rule catalogue

> Generated from `iam_pathfinder.rules.ALL_RULES` by
> `python docs/generate_rules_md.py`. Do not edit by hand: the test
> suite regenerates this file and fails if it drifts from the code.

**23 rules** (4 combination, 12 escalation, 7 hygiene).

## Summary

| Rule id | Severity | Category | Principals | Title |
| --- | --- | --- | --- | --- |
| [`IAM_CREATE_POLICY_VERSION`](#iam_create_policy_version) | high | escalation | user, role | Create a new version of an IAM policy the principal can modify |
| [`IAM_SET_DEFAULT_POLICY_VERSION`](#iam_set_default_policy_version) | medium | escalation | user, role | Activate a different version of an IAM policy |
| [`IAM_ATTACH_USER_POLICY`](#iam_attach_user_policy) | high | escalation | user, role | Attach a managed policy to an IAM user |
| [`IAM_ATTACH_GROUP_POLICY`](#iam_attach_group_policy) | high | escalation | user, role | Attach a managed policy to an IAM group |
| [`IAM_ATTACH_ROLE_POLICY`](#iam_attach_role_policy) | high | escalation | user, role | Attach a managed policy to an IAM role |
| [`IAM_PUT_USER_POLICY`](#iam_put_user_policy) | high | escalation | user, role | Write an inline policy onto an IAM user |
| [`IAM_PUT_GROUP_POLICY`](#iam_put_group_policy) | high | escalation | user, role | Write an inline policy onto an IAM group |
| [`IAM_PUT_ROLE_POLICY`](#iam_put_role_policy) | high | escalation | user, role | Write an inline policy onto an IAM role |
| [`IAM_ADD_USER_TO_GROUP`](#iam_add_user_to_group) | high | escalation | user, role | Add a user to an IAM group |
| [`IAM_CREATE_ACCESS_KEY`](#iam_create_access_key) | high | escalation | user, role | Create access keys for other IAM users |
| [`IAM_LOGIN_PROFILE`](#iam_login_profile) | high | escalation | user, role | Create or reset console passwords for other IAM users |
| [`IAM_UPDATE_ASSUME_ROLE_POLICY`](#iam_update_assume_role_policy) | high | escalation | user, role | Rewrite a role's trust policy, then assume the role |
| [`PASSROLE_EC2_RUNINSTANCES`](#passrole_ec2_runinstances) | high | combination | user, role | Pass a role to a new EC2 instance (instance profile) |
| [`PASSROLE_LAMBDA_CREATE_INVOKE`](#passrole_lambda_create_invoke) | high | combination | user, role | Pass a role to a new Lambda function, then invoke it |
| [`PASSROLE_CLOUDFORMATION_CREATE_STACK`](#passrole_cloudformation_create_stack) | high | combination | user, role | Pass a role to a new CloudFormation stack |
| [`PASSROLE_WILDCARD`](#passrole_wildcard) | medium | combination | user, role | iam:PassRole with Resource: * |
| [`FULL_ADMIN`](#full_admin) | critical | hygiene | user, role, group | Principal has full administrator access (Action: * on Resource: *) |
| [`SERVICE_WILDCARD`](#service_wildcard) | medium | hygiene | user, role, group | Service-wide wildcard permission (e.g. iam:*) |
| [`BROAD_NOT_ACTION`](#broad_not_action) | medium | hygiene | user, role, group | Allow with NotAction grants broad access |
| [`STS_ASSUMEROLE_WILDCARD`](#sts_assumerole_wildcard) | medium | hygiene | user, role, group | sts:AssumeRole with Resource: * |
| [`TRUST_POLICY_PUBLIC`](#trust_policy_public) | high | hygiene | role | Role trust policy allows any principal (*) |
| [`TRUST_POLICY_CROSS_ACCOUNT`](#trust_policy_cross_account) | medium | hygiene | role | Role trusts an external AWS account without sts:ExternalId |
| [`TRUST_POLICY_ACCOUNT_ROOT`](#trust_policy_account_root) | low | hygiene | role | Role trusts the account root (informational) |

Severity is the default severity for the rule; a finding can be graded
higher or lower per principal (for example `FULL_ADMIN` is `critical` for
a user but `high` for a role or group, and `NotAction`-derived findings
are capped at medium confidence). Confidence is reported separately:
`high` for unconditional statements, `medium` when a `Condition` applies
or `NotAction` is involved, `low` when an explicit deny narrows the
usable scope.

## IAM_CREATE_POLICY_VERSION

* **Title:** Create a new version of an IAM policy the principal can modify
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:CreatePolicyVersion`

iam:CreatePolicyVersion lets this principal create a new version of the listed IAM policies, and the --set-as-default flag makes it active without needing iam:SetDefaultPolicyVersion. The new version can grant any permissions, so whoever controls this principal can turn one of these policies into an administrator policy and inherit its permissions.

**Remediation.** Remove iam:CreatePolicyVersion from the principal's policies. Where IAM access is genuinely needed, scope Resource to specific read-only policy ARNs, or delegate policy management to a dedicated administrative role with permissions boundaries.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_SET_DEFAULT_POLICY_VERSION

* **Title:** Activate a different version of an IAM policy
* **Severity:** medium
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:SetDefaultPolicyVersion`

iam:SetDefaultPolicyVersion switches which stored version of a policy is active. If any non-default version is broader than the current one (common after a policy was 'tightened'), this principal can reactivate it and gain the older permissions. If the principal also holds iam:CreatePolicyVersion, the effect is full control over the policy.

**Remediation.** Remove iam:SetDefaultPolicyVersion, or scope Resource to policies that have a single, reviewed version. Audit non-default policy versions: delete versions that are no longer needed so they cannot be reactivated.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_ATTACH_USER_POLICY

* **Title:** Attach a managed policy to an IAM user
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:AttachUserPolicy`

iam:AttachUserPolicy binds a managed policy's permissions to a user. This principal can attach an administrator policy (for example arn:aws:iam::aws:policy/AdministratorAccess) to a user it controls and immediately receive those permissions.

**Remediation.** Remove iam:AttachUserPolicy or restrict Resource to the principal's own user ARN only if self-service attachment is required (ideally limited to non-privileged, reviewable policies). Never grant it on '*' with access to AdministratorAccess or similar policies.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_ATTACH_GROUP_POLICY

* **Title:** Attach a managed policy to an IAM group
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:AttachGroupPolicy`

iam:AttachGroupPolicy binds a managed policy's permissions to a group. A member of the target group receives the new permissions, so a user who can attach an administrator policy to one of their own groups gains full admin access.

**Remediation.** Remove iam:AttachGroupPolicy or scope Resource to specific groups the principal does not belong to and never to '*' combined with access to privileged policies.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_ATTACH_ROLE_POLICY

* **Title:** Attach a managed policy to an IAM role
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:AttachRolePolicy`

iam:AttachRolePolicy binds a managed policy's permissions to a role. If the principal can also assume the target role, attaching an administrator policy to it and then assuming it yields full admin access.

**Remediation.** Remove iam:AttachRolePolicy or scope Resource away from roles this principal can assume. Review every role that allows this principal to sts:AssumeRole - the combination is the escalation path.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_PUT_USER_POLICY

* **Title:** Write an inline policy onto an IAM user
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:PutUserPolicy`

iam:PutUserPolicy replaces or creates an inline policy on a user. The policy document is chosen by the caller, so this principal can write an administrator policy onto a user it controls and receive those permissions.

**Remediation.** Remove iam:PutUserPolicy or scope Resource to users other than the principal itself. Treat any Put*Policy permission on '*' as equivalent to admin access.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_PUT_GROUP_POLICY

* **Title:** Write an inline policy onto an IAM group
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:PutGroupPolicy`

iam:PutGroupPolicy replaces or creates an inline policy on a group. Every member of the group gains the new permissions, so a member who can write an administrator policy onto their own group gains full admin access.

**Remediation.** Remove iam:PutGroupPolicy or scope Resource away from groups this principal belongs to. Never allow it on '*' for groups that hold privileged permissions.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_PUT_ROLE_POLICY

* **Title:** Write an inline policy onto an IAM role
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:PutRolePolicy`

iam:PutRolePolicy replaces or creates an inline policy on a role. If the principal can also assume the target role, writing an administrator inline policy onto it and assuming it yields full admin access.

**Remediation.** Remove iam:PutRolePolicy or scope Resource away from roles this principal can assume. Audit who can sts:AssumeRole each affected role.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_ADD_USER_TO_GROUP

* **Title:** Add a user to an IAM group
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:AddUserToGroup`

iam:AddUserToGroup changes group membership. A principal who can add itself to a privileged group inherits every permission that group grants. Group membership is the standard way AWS administrators grant permissions, so compromising a principal that can edit membership is usually a direct path to admin.

**Remediation.** Remove iam:AddUserToGroup or scope Resource to specific non-privileged groups. Never grant membership editing on '*' to non-administrators, and avoid groups that combine broad permissions with editable membership.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_CREATE_ACCESS_KEY

* **Title:** Create access keys for other IAM users
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:CreateAccessKey`

iam:CreateAccessKey issues a new access key pair for an IAM user. Access keys are long-lived credentials that carry exactly the victim user's permissions, so creating a key for a more-privileged user and using it from anywhere yields that user's access without needing their existing credentials.

**Remediation.** Remove iam:CreateAccessKey or scope Resource with ${aws:username} (arn:aws:iam::ACCOUNT:user/${aws:username}) so principals can only manage their own keys. Enable access-key age alerts and review IAM credential reports regularly.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_LOGIN_PROFILE

* **Title:** Create or reset console passwords for other IAM users
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`

iam:CreateLoginProfile gives an IAM user a console password and iam:UpdateLoginProfile changes an existing one. Either lets this principal sign in to the AWS console as a more-privileged user with a password of its choosing.

**Remediation.** Remove iam:CreateLoginProfile/iam:UpdateLoginProfile or scope them with ${aws:username} so principals only manage their own password. Require MFA for console users and alert on login-profile changes.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html>

## IAM_UPDATE_ASSUME_ROLE_POLICY

* **Title:** Rewrite a role's trust policy, then assume the role
* **Severity:** high
* **Category:** escalation
* **Principals:** user, role
* **Required permissions:** `iam:UpdateAssumeRolePolicy`, `sts:AssumeRole`

iam:UpdateAssumeRolePolicy rewrites who is allowed to assume a role. Combined with sts:AssumeRole permission on the same role, this principal can add itself to the role's trust policy and then assume it, acting with everything the role can do.

**Remediation.** Remove iam:UpdateAssumeRolePolicy or scope Resource away from roles this principal can assume. Restrict sts:AssumeRole at the same time: the pair is the escalation path, and either permission alone is not.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

## PASSROLE_EC2_RUNINSTANCES

* **Title:** Pass a role to a new EC2 instance (instance profile)
* **Severity:** high
* **Category:** combination
* **Principals:** user, role
* **Required permissions:** `iam:PassRole`, `ec2:RunInstances`

iam:PassRole plus ec2:RunInstances lets this principal launch an EC2 instance with an instance profile of its choosing. The instance receives the role's credentials via the instance metadata service, so whoever can log into or run code on that instance acts with the role's permissions.

**Remediation.** Remove ec2:RunInstances or iam:PassRole from this principal. Scope iam:PassRole Resource to specific service roles that never hold admin/escalation permissions, and require instance-launch policies to pin allowed AMIs, instance types and IAM instance profiles.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>

## PASSROLE_LAMBDA_CREATE_INVOKE

* **Title:** Pass a role to a new Lambda function, then invoke it
* **Severity:** high
* **Category:** combination
* **Principals:** user, role
* **Required permissions:** `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction`

iam:PassRole with lambda:CreateFunction and lambda:InvokeFunction lets this principal deploy a Lambda function that runs under a role of its choosing and then trigger it. The function's code executes with the role's permissions, so a privileged role in scope means full compromise of whatever that role can do.

**Remediation.** Remove lambda:CreateFunction/lambda:InvokeFunction or restrict iam:PassRole to non-privileged, task-specific roles. Review existing Lambda functions for unexpected roles and unexpected invokers.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>

## PASSROLE_CLOUDFORMATION_CREATE_STACK

* **Title:** Pass a role to a new CloudFormation stack
* **Severity:** high
* **Category:** combination
* **Principals:** user, role
* **Required permissions:** `iam:PassRole`, `cloudformation:CreateStack`

iam:PassRole with cloudformation:CreateStack lets this principal create a stack whose resources are created using a service role of its choosing. A template can create administrative users, policies or other resources with that role's permissions.

**Remediation.** Remove cloudformation:CreateStack or restrict iam:PassRole to non-privileged stack roles. Use CloudFormation service-managed permissions (service-managed lifecycle) where possible instead of customer-passed roles.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>

## PASSROLE_WILDCARD

* **Title:** iam:PassRole with Resource: *
* **Severity:** medium
* **Category:** combination
* **Principals:** user, role
* **Required permissions:** `iam:PassRole`

iam:PassRole on Resource: * lets this principal hand ANY role in the account to a service that runs code on its behalf (EC2, Lambda, CloudFormation, Glue, Data Pipeline and others). Even without a known pairing today, any future service permission - or a service this tool does not model - turns this into privilege escalation.

**Remediation.** Scope iam:PassRole Resource to the specific role ARNs this principal legitimately needs to pass, and never to '*'. Pair the scoped roles with permissions-boundaried, task-specific policies.

**References.**

* <https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

## FULL_ADMIN

* **Title:** Principal has full administrator access (Action: * on Resource: *)
* **Severity:** critical
* **Category:** hygiene
* **Principals:** user, role, group
* **Required permissions:** `*`

This principal's policies grant every action on every resource with no conditions. For a user this means long-lived credentials (access keys, console password) can do anything in the account, including deleting log trails and granting itself new permissions. Admin access is sometimes intentional, but it should be an explicit, reviewed exception rather than a default.

**Remediation.** Replace standing admin with permission sets / roles that require recent authentication (SSO, federation), MFA and short sessions. Scope admin policies with permissions boundaries and deny dangerous actions (iam:*, account-level changes) with explicit Deny statements.

**References.**

* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

## SERVICE_WILDCARD

* **Title:** Service-wide wildcard permission (e.g. iam:*)
* **Severity:** medium
* **Category:** hygiene
* **Principals:** user, role, group
* **Required permissions:** `<service>:*`

A pattern such as iam:* or s3:* grants every action of that service on the scoped resources. For the IAM service this is effectively administration of the identity plane (create users, keys, policies), which is a documented path to full account compromise; for other services it removes any least-privilege granularity within the service.

**Remediation.** Replace service-wide wildcards with the specific actions the workload needs. If broad access is required, scope it tightly by Resource and review it as an exception.

**References.**

* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

## BROAD_NOT_ACTION

* **Title:** Allow with NotAction grants broad access
* **Severity:** medium
* **Category:** hygiene
* **Principals:** user, role, group
* **Required permissions:** `<everything except listed>`

A statement with NotAction inverts its action list: it allows every action EXCEPT the listed ones. On Resource: * this grants almost the whole account - the security impact depends on how much is excluded, which is why this rule reports the excluded list.

**Remediation.** Rewrite NotAction statements as explicit allow lists of the actions actually needed. If a small exclusion list was used to mean 'everything else', enumerate those actions instead.

**References.**

* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

## STS_ASSUMEROLE_WILDCARD

* **Title:** sts:AssumeRole with Resource: *
* **Severity:** medium
* **Category:** hygiene
* **Principals:** user, role, group
* **Required permissions:** `sts:AssumeRole`

sts:AssumeRole on Resource: * lets this principal assume ANY role that trusts it. Combined with roles that trust the account root or have weak trust policies, this usually means every such role is reachable; whether that is an escalation depends on which roles trust this principal and what they can do.

**Remediation.** Scope sts:AssumeRole Resource to the specific roles this principal needs. Review roles whose trust includes this principal (or the account root) - they are the ones actually reachable.

**References.**

* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

## TRUST_POLICY_PUBLIC

* **Title:** Role trust policy allows any principal (*)
* **Severity:** high
* **Category:** hygiene
* **Principals:** role
* **Required permissions:** `sts:AssumeRole`

The role's trust policy has Principal "*" with no condition, so any AWS principal that holds sts:AssumeRole permission on this role - including in-account principals with AssumeRole on '*' - is allowed to assume it. Public trusts are safe only when a restrictive Condition is present; this one has none.

**Remediation.** Replace Principal "*" with the specific accounts, roles or services that need to assume the role, or add a restrictive condition (for example sts:ExternalId for cross-account access, or aws:PrincipalOrgID within an organization).

**References.**

* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

## TRUST_POLICY_CROSS_ACCOUNT

* **Title:** Role trusts an external AWS account without sts:ExternalId
* **Severity:** medium
* **Category:** hygiene
* **Principals:** role
* **Required permissions:** `sts:AssumeRole`

The role trusts principals from a different AWS account. Without an sts:ExternalId condition, any principal in that external account which holds sts:AssumeRole on this role can assume it - and if the external account is ever compromised, every role trusting it is too. ExternalId proves the role is being assumed by the intended integration rather than a lookalike.

**Remediation.** Add an sts:ExternalId condition with a unique, secret external id for third-party integrations, or replace the external account principal with the specific external role/user ARNs that need access. If the trust is no longer needed, remove it.

**References.**

* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html>
* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

## TRUST_POLICY_ACCOUNT_ROOT

* **Title:** Role trusts the account root (informational)
* **Severity:** low
* **Category:** hygiene
* **Principals:** role
* **Required permissions:** `sts:AssumeRole`

The role's trust policy includes this account's root principal (arn:aws:iam::ACCOUNT:root). That means any principal inside this account that holds sts:AssumeRole permission on this role can assume it - the common 'account delegation' pattern. It is informational here because it is usually intentional, but it makes any wildcard sts:AssumeRole permission immediately meaningful.

**Remediation.** If the delegation is intentional, keep it and make sure no principal holds sts:AssumeRole on '*' unnecessarily. Otherwise replace the root principal with the specific roles/users that need access.

**References.**

* <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>
