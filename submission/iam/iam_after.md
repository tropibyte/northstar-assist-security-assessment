# IAM after-state audit

Source: **captured iam/before vs iam/after** | Account: `n/a` | Generated: 2026-09-20T00:01:53+00:00

**Verdict: PASS**

- Statements compared: 37
- Narrowed: 5 | Removed: 14 | Unchanged: 18
- Widened but declared and argued: 0
- **Widened, undeclared: 0**
- Surviving wildcards: 17 (7 bare, 10 partial)
- **Unjustified wildcards: 0**

## Surviving wildcards

| Role | Statement | Resource | Class | Justification |
| --- | --- | --- | --- | --- |
| gateway | `GetGateway` | `arn:aws:bedrock-agentcore:us-east-1:118924230273:gateway/northstar-assist-gateway-lhirtedegn/*` | SCOPED | Scoped to this gateway; the `*` covers its own sub-resources. Read-only. |
| harness | `BedrockMantleCallWithBearerToken` | `*` | UNAVOIDABLE | Bearer-token exchange is an identity operation with no resource to name. `bedrock-mantle` is an undocumented internal service backing AgentCore inference; it publishes no resource-level ARNs for this action. |
| harness | `EcrPublicTokenAccess` | `*` | UNAVOIDABLE | `ecr-public:GetAuthorizationToken` returns a registry-wide credential and is documented by AWS as not supporting resource-level permissions. |
| harness | `StsForEcrPublicPull` | `*` | UNAVOIDABLE | STS bearer-token issuance takes no resource. Constrained in practice by the ECR Public pull it authorises, not by ARN. |
| harness | `EcrManagedImagePull` | `arn:aws:ecr:us-east-1:*:repository/harness-*` | SCOPED | Repository prefix is pinned to `harness-*`. The remaining `*` is the ACCOUNT field, because AWS publishes AgentCore harness runtime images from an AWS-owned account whose ID is not documented. Read-only image pull; it cannot push or delete. |
| harness | `EcrManagedImageToken` | `*` | UNAVOIDABLE | Same as the public variant: the authorization token is registry-scoped, and ECR does not accept a repository ARN on this action. |
| harness | `XRayTracingAccess` | `*` | UNAVOIDABLE | X-Ray segment ingestion has no resource model; AWS documents these four actions as requiring Resource "*". Write-only telemetry -- it cannot read traces. |
| harness | `CloudWatchLogsGroup` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/runtimes/*` | SCOPED | Restricted to AgentCore runtime log groups. Deliberately excludes /northstar-assist/model-invocations: the agent's identity must not be able to write to the log that records its own behaviour (threat R-02). |
| harness | `CloudWatchLogsGroup` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*` | SCOPED | Restricted to AgentCore runtime log groups. Deliberately excludes /northstar-assist/model-invocations: the agent's identity must not be able to write to the log that records its own behaviour (threat R-02). |
| harness | `CloudWatchLogsDescribeGroups` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/runtimes/*` | SCOPED | Metadata read over runtime log groups only. Does not reach the model-invocation log group. |
| harness | `CloudWatchLogsDescribeGroups` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*` | SCOPED | Metadata read over runtime log groups only. Does not reach the model-invocation log group. |
| harness | `CloudWatchLogsStream` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/runtimes/*:log-stream:*` | SCOPED | Write path for the runtime's own operational logs, scoped to runtime groups and their streams. The invocation audit log is out of reach by design. |
| harness | `CloudWatchLogsPutResourcePolicy` | `arn:aws:logs:us-east-1:118924230273:log-group:/aws/bedrock-agentcore/runtimes/harness_NorthstarAssist-*` | SCOPED | Tightest of the four: this harness's own runtime log group only. |
| harness | `CloudWatchMetricsPublish` | `*` | UNAVOIDABLE | PutMetricData supports no resource-level permission. Narrowed in practice by the cloudwatch:namespace condition key, which is the only available control. |
| harness | `AgentCoreWorkloadIdentity` | `arn:aws:bedrock-agentcore:us-east-1:118924230273:workload-identity-directory/default/workload-identity/harness_NorthstarAssist-*` | SCOPED | Scoped to this harness's own workload identity; the `*` covers only the generated suffix AgentCore appends to the harness name. It reaches no other workload. |
| kb | `CloudWatchWritePermissionStatement` | `*` | UNAVOIDABLE | Identical to the harness case: the knowledge base publishes ingestion metrics and PutMetricData cannot be resource-scoped. |
| kb | `S3GetObjectStatement` | `arn:aws:s3:::northstar-assist-kb-41071520/*` | SCOPED | Objects within the corpus bucket only -- the textbook least-privilege shape for this action, and further constrained by an aws:ResourceAccount condition. The console generated this correctly; hardening leaves it untouched. |

## Every statement

| Role | Statement | Verdict | Detail |
| --- | --- | --- | --- |
| gateway | `AllowBedrockAgenticRetrieveFromKnowledgeBase` | REMOVED | statement deleted entirely |
| gateway | `AllowBedrockApplyGuardrailForKnowledgeBase` | REMOVED | statement deleted entirely |
| gateway | `AllowBedrockGetInferenceProfileForKnowledgeBase` | REMOVED | statement deleted entirely |
| gateway | `AllowBedrockGetKnowledgeBaseFromKnowledgeBase` | UNCHANGED | identical to the console original |
| gateway | `AllowBedrockInvokeModelForKnowledgeBase` | NARROWED | resources 4 -> 1 |
| gateway | `AllowBedrockRerankForKnowledgeBase` | REMOVED | statement deleted entirely |
| gateway | `AllowBedrockRetrieveFromKnowledgeBase` | UNCHANGED | identical to the console original |
| gateway | `GetConfigurationBundleVersion` | REMOVED | statement deleted entirely |
| gateway | `GetGateway` | NARROWED | resources 1 -> 2 |
| harness | `AgentCoreBrowserDefault` | REMOVED | statement deleted entirely |
| harness | `AgentCoreCodeInterpreterDefault` | REMOVED | statement deleted entirely |
| harness | `AgentCoreGatewayAccess` | UNCHANGED | identical to the console original |
| harness | `AgentCoreMemory` | REMOVED | statement deleted entirely |
| harness | `AgentCoreWorkloadIdentity` | UNCHANGED | identical to the console original |
| harness | `ApplyNorthstarGuardrail` | UNCHANGED | identical to the console original |
| harness | `BedrockMantleCallWithBearerToken` | UNCHANGED | identical to the console original |
| harness | `BedrockMantleInference` | REMOVED | statement deleted entirely |
| harness | `BedrockModelInvocation` | NARROWED | resources 2 -> 4 |
| harness | `CloudWatchLogsDescribeGroups` | NARROWED | resources 1 -> 2 |
| harness | `CloudWatchLogsGroup` | NARROWED | resources 1 -> 2 |
| harness | `CloudWatchLogsPutResourcePolicy` | UNCHANGED | identical to the console original |
| harness | `CloudWatchLogsStream` | UNCHANGED | identical to the console original |
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
| kb | `MarketplaceOperationsFromBedrockFor3pModels` | REMOVED | statement deleted entirely |
| kb | `S3GetObjectStatement` | UNCHANGED | identical to the console original |
| kb | `S3ListBucketStatement` | UNCHANGED | identical to the console original |
