# IAM after-state audit

Source: **captured iam/before vs iam/after** | Account: `n/a` | Generated: 2026-09-19T17:34:49+00:00

**Verdict: FAIL**

- Statements compared: 37
- Narrowed: 5 | Removed: 9 | Unchanged: 18
- Widened but declared and argued: 1
- **Widened, undeclared: 4**
- Surviving wildcards: 23 (8 bare, 15 partial)
- **Unjustified wildcards: 12**

## Widened statements - these fail the audit

| Role | Statement | Detail |
| --- | --- | --- |
| harness | `CloudWatchLogsGroup` | resources not covered by BEFORE: ['arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*', 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*'] |
| harness | `CloudWatchLogsStream` | resources not covered by BEFORE: ['arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*', 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*'] |
| harness | `CloudWatchLogsPutResourcePolicy` | resources not covered by BEFORE: ['arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*', 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*'] |
| kb | `S3GetObjectStatement` | resources not covered by BEFORE: ['arn:aws:s3:::northstar-assist-kb-41071520'] |

## Declared new grants

Additions the hardening makes deliberately. Each must name every resource the original did not cover, with a reason.

| Role | Statement | Reason | Net effect |
| --- | --- | --- | --- |
| gateway | `AllowBedrockApplyGuardrailForKnowledgeBase` | A STANDARD-tier guardrail is invoked through a cross-Region guardrail PROFILE, and the profile ARN is regional and follows request routing. bedrock:ApplyGuardrail must therefore be granted on the profile in every region the profile routes to (us-east-1, us-east-2, us-west-2) or calls 403 intermittently. The console's sample policy grants only `guardrail/*` and cannot work at STANDARD tier. | Net narrowing. The guardrail dimension goes from `guardrail/*` -- every guardrail in the account -- to this one guardrail ID. The profile ARNs are a new resource TYPE that the original did not address, not a broadening of the original grant. |

## Surviving wildcards

| Role | Statement | Resource | Class | Justification |
| --- | --- | --- | --- | --- |
| gateway | `GetGateway` | `arn:aws:bedrock-agentcore:us-east-1:118924230273:gateway/northstar-assist-gateway-1jkdshz4iy/*` | SCOPED | Scoped to this gateway; the `*` covers its own sub-resources. Read-only. |
| gateway | `GetConfigurationBundleVersion` | `arn:aws:bedrock-agentcore:us-east-1:118924230273:configuration-bundle/*` | NECESSARY **(UNJUSTIFIED)** | NECESSARY requires an 'evidence' pointer to an ablation run showing removal breaks the system |
| gateway | `AllowBedrockGetInferenceProfileForKnowledgeBase` | `arn:aws:bedrock:us-east-1:118924230273:inference-profile/*` | NECESSARY **(UNJUSTIFIED)** | NECESSARY requires an 'evidence' pointer to an ablation run showing removal breaks the system |
| harness | `BedrockMantleInference` | `arn:aws:bedrock-mantle:us-east-1:118924230273:*` | NECESSARY **(UNJUSTIFIED)** | NECESSARY requires an 'evidence' pointer to an ablation run showing removal breaks the system |
| harness | `BedrockMantleCallWithBearerToken` | `*` | UNAVOIDABLE | Bearer-token exchange is an identity operation with no resource to name. `bedrock-mantle` is an undocumented internal service backing AgentCore inference; it publishes no resource-level ARNs for this action. |
| harness | `EcrPublicTokenAccess` | `*` | UNAVOIDABLE | `ecr-public:GetAuthorizationToken` returns a registry-wide credential and is documented by AWS as not supporting resource-level permissions. |
| harness | `StsForEcrPublicPull` | `*` | UNAVOIDABLE | STS bearer-token issuance takes no resource. Constrained in practice by the ECR Public pull it authorises, not by ARN. |
| harness | `EcrManagedImagePull` | `arn:aws:ecr:us-east-1:*:repository/harness-*` | SCOPED | Repository prefix is pinned to `harness-*`. The remaining `*` is the ACCOUNT field, because AWS publishes AgentCore harness runtime images from an AWS-owned account whose ID is not documented. Read-only image pull; it cannot push or delete. |
| harness | `EcrManagedImageToken` | `*` | UNAVOIDABLE | Same as the public variant: the authorization token is registry-scoped, and ECR does not accept a repository ARN on this action. |
| harness | `XRayTracingAccess` | `*` | UNAVOIDABLE | X-Ray segment ingestion has no resource model; AWS documents these four actions as requiring Resource "*". Write-only telemetry -- it cannot read traces. |
| harness | `CloudWatchLogsGroup` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*` | SCOPED **(UNJUSTIFIED)** | live resource 'arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*' does not match registered pattern 'arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/*' |
| harness | `CloudWatchLogsGroup` | `arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*` | SCOPED **(UNJUSTIFIED)** | live resource 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*' does not match registered pattern 'arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/*' |
| harness | `CloudWatchLogsDescribeGroups` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*` | SCOPED **(UNJUSTIFIED)** | live resource 'arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*' does not match registered pattern 'arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/*' |
| harness | `CloudWatchLogsDescribeGroups` | `arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*` | SCOPED **(UNJUSTIFIED)** | live resource 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*' does not match registered pattern 'arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/*' |
| harness | `CloudWatchLogsStream` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*` | SCOPED **(UNJUSTIFIED)** | live resource 'arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*' does not match registered pattern 'arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/*' |
| harness | `CloudWatchLogsStream` | `arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*` | SCOPED **(UNJUSTIFIED)** | live resource 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*' does not match registered pattern 'arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/*' |
| harness | `CloudWatchLogsPutResourcePolicy` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*` | SCOPED **(UNJUSTIFIED)** | live resource 'arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*' does not match registered pattern 'arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/harness_NorthstarAssist-*' |
| harness | `CloudWatchLogsPutResourcePolicy` | `arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*` | SCOPED **(UNJUSTIFIED)** | live resource 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*' does not match registered pattern 'arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/runtimes/harness_NorthstarAssist-*' |
| harness | `CloudWatchMetricsPublish` | `*` | UNAVOIDABLE | PutMetricData supports no resource-level permission. Narrowed in practice by the cloudwatch:namespace condition key, which is the only available control. |
| harness | `AgentCoreWorkloadIdentity` | `arn:aws:bedrock-agentcore:us-east-1:118924230273:workload-identity-directory/default/workload-identity/harness_NorthstarAssist-*` | SCOPED | Scoped to this harness's own workload identity; the `*` covers only the generated suffix AgentCore appends to the harness name. It reaches no other workload. |
| kb | `CloudWatchWritePermissionStatement` | `*` | UNAVOIDABLE | Identical to the harness case: the knowledge base publishes ingestion metrics and PutMetricData cannot be resource-scoped. |
| kb | `MarketplaceOperationsFromBedrockFor3pModels` | `*` | UNJUSTIFIED **(UNJUSTIFIED)** | no entry for 'kb/MarketplaceOperationsFromBedrockFor3pModels' in wildcard-register.json |
| kb | `S3GetObjectStatement` | `arn:aws:s3:::northstar-assist-kb-41071520/*` | SCOPED | Objects within the corpus bucket only -- the textbook least-privilege shape for this action, and further constrained by an aws:ResourceAccount condition. The console generated this correctly; hardening leaves it untouched. |

## Every statement

| Role | Statement | Verdict | Detail |
| --- | --- | --- | --- |
| gateway | `AllowBedrockAgenticRetrieveFromKnowledgeBase` | REMOVED | statement deleted entirely |
| gateway | `AllowBedrockApplyGuardrailForKnowledgeBase` | WIDENED-DECLARED | declared new grant: ['arn:aws:bedrock:us-east-1:118924230273:guardrail-profile/us.guardrail.v1:0', 'arn:aws:bedrock:us-east-2:118924230273:guardrail-profile/us.guardrail.v1:0', 'arn:aws:bedrock:us-west-2:118924230273:guardrail-profile/us.guardrail.v1:0']. Net narrowing. The guardrail dimension goes from `guardrail/*` -- every guardrail in the account -- to this one guardrail ID. The profile ARNs are a new resource TYPE that the original did not address, not a broadening of the original grant. |
| gateway | `AllowBedrockGetInferenceProfileForKnowledgeBase` | UNCHANGED | identical to the console original |
| gateway | `AllowBedrockGetKnowledgeBaseFromKnowledgeBase` | UNCHANGED | identical to the console original |
| gateway | `AllowBedrockInvokeModelForKnowledgeBase` | NARROWED | resources 4 -> 1 |
| gateway | `AllowBedrockRerankForKnowledgeBase` | REMOVED | statement deleted entirely |
| gateway | `AllowBedrockRetrieveFromKnowledgeBase` | UNCHANGED | identical to the console original |
| gateway | `GetConfigurationBundleVersion` | UNCHANGED | identical to the console original |
| gateway | `GetGateway` | NARROWED | resources 1 -> 2 |
| harness | `AgentCoreBrowserDefault` | REMOVED | statement deleted entirely |
| harness | `AgentCoreCodeInterpreterDefault` | REMOVED | statement deleted entirely |
| harness | `AgentCoreGatewayAccess` | UNCHANGED | identical to the console original |
| harness | `AgentCoreMemory` | REMOVED | statement deleted entirely |
| harness | `AgentCoreWorkloadIdentity` | UNCHANGED | identical to the console original |
| harness | `ApplyNorthstarGuardrail` | UNCHANGED | identical to the console original |
| harness | `BedrockMantleCallWithBearerToken` | UNCHANGED | identical to the console original |
| harness | `BedrockMantleInference` | UNCHANGED | identical to the console original |
| harness | `BedrockModelInvocation` | NARROWED | resources 2 -> 4 |
| harness | `CloudWatchLogsDescribeGroups` | NARROWED | resources 1 -> 2 |
| harness | `CloudWatchLogsGroup` | WIDENED | resources not covered by BEFORE: ['arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*', 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*'] |
| harness | `CloudWatchLogsPutResourcePolicy` | WIDENED | resources not covered by BEFORE: ['arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*', 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*'] |
| harness | `CloudWatchLogsStream` | WIDENED | resources not covered by BEFORE: ['arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/*', 'arn:aws:logs:us-east-1:118924230273:log-group:/northstar-assist/model-invocations:*'] |
| harness | `CloudWatchMetricsPublish` | UNCHANGED | identical to the console original |
| harness | `EFSClientAccess` | REMOVED | statement deleted entirely |
| harness | `EFSDescribe` | REMOVED | statement deleted entirely |
| harness | `EcrManagedImagePull` | UNCHANGED | identical to the console original |
| harness | `EcrManagedImageToken` | UNCHANGED | identical to the console original |
| harness | `EcrPublicTokenAccess` | UNCHANGED | identical to the console original |
| harness | `S3FilesClientAccess` | REMOVED | statement deleted entirely |
| harness | `S3FilesDescribe` | REMOVED | statement deleted entirely |
| harness | `StsForEcrPublicPull` | UNCHANGED | identical to the console original |
| harness | `XRayTracingAccess` | UNCHANGED | identical to the console original |
| kb | `BedrockInvokeModelStatement` | UNCHANGED | identical to the console original |
| kb | `CloudWatchWritePermissionStatement` | UNCHANGED | identical to the console original |
| kb | `MarketplaceOperationsFromBedrockFor3pModels` | NARROWED | actions removed: 1 |
| kb | `S3GetObjectStatement` | WIDENED | resources not covered by BEFORE: ['arn:aws:s3:::northstar-assist-kb-41071520'] |
| kb | `S3ListBucketStatement` | UNCHANGED | identical to the console original |
