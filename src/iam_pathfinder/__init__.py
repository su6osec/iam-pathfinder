"""iam-pathfinder: offline AWS IAM privilege-escalation and risky-permission analyzer.

The package never imports an AWS SDK and never opens a network connection;
it only reads a local JSON file produced by ``aws iam get-account-authorization-details``.
"""

__version__ = "0.1.0"

#: Canonical repository URL (also used as SARIF ``informationUri``).
REPOSITORY_URL = "https://github.com/su6osec/iam-pathfinder"
