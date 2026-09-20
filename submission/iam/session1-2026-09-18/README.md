# Session 1 IAM evidence — 18 September 2026 (superseded)

This is the *original* capture, kept unedited. It is the record of the defect
the post-submission review found, and it is deliberately not corrected:
a before/after evidence set that has been retouched is worth nothing.

Audited by `22_iam_audit.py`, it fails with four undeclared widenings:

| Statement | Before | After |
| --- | --- | --- |
| `harness/CloudWatchLogsGroup` | `/aws/bedrock-agentcore/runtimes/*` | `/aws/bedrock-agentcore/*` + the invocation log group |
| `harness/CloudWatchLogsStream` | `…/runtimes/*:log-stream:*` | same widening |
| `harness/CloudWatchLogsPutResourcePolicy` | `…/runtimes/harness_NorthstarAssist-*` | same widening |
| `kb/S3GetObjectStatement` | `bucket/*` | `bucket` + `bucket/*` |

The first three are the logging regression described in
`docs/iam-hardening-summary.md` §0. The fourth was found later, by the auditor
itself, and appears in no review: the console's knowledge-base S3 policy was
already correctly least-privilege and the hardening pass made it broader.

Both have one root cause. `resolve_targets()` returned a single ARN list per
service for the whole role, and it was applied to every statement of that
service, discarding each statement's own tighter scope. The deeper fault is
that the narrowing pass never checked that it had narrowed.

The live after-state in `../before` and `../after` is the corrected rebuild
(session 2), which the same auditor passes.
