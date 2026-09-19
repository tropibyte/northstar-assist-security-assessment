# Console screenshot evidence

41 unique screenshots captured during the build, test and teardown of Northstar
Assist on 18 September 2026, in chronological order. Three exact duplicates
were removed by hash before filing.

**On provenance, stated plainly.** These were captured live during the session
and pasted into the working conversation as the build progressed; they were
saved to disk afterwards from that conversation. They are unedited screen
captures — no cropping, annotation or redaction — which is why the account ID,
resource IDs and browser chrome are all visible. The AWS account
(118924230273) was a temporary Udacity Cloud Lab account and has been torn
down.

Filenames are `NN_xxxxxx.png`, where `NN` is capture order.

## Rubric-relevant screenshots — individually verified

Each of these was opened and confirmed to show what the caption claims.

| File | Shows | Satisfies |
| --- | --- | --- |
| **`20_516918.png`** | `Northstar-Kb Retrieve` tool-call panel: `retrievalQuery` text, 5 `retrievalResults`, `documentId` (`s3://northstar-assist-kb-41071520/…`), `s3Location`, full metadata including `_document_title: company_policies_handbook.html`, `_chunk_id`, `_data_source_id`, and relevance `score` | **Task 1** — agent retrieves content from the knowledge source. The primary retrieval evidence. |
| **`21_525722.png`** | Harness playground, full exchange: prompt "What is Northstar's hybrid work policy? Name the source document.", **Agent trace (1 steps)** showing the Retrieve call, the grounded answer, and the model naming `company_policies_handbook.html` as its source. Token counts (3,840 in / 138 out) and 1,331 ms latency visible. Configs pane shows Nova 2 Lite and the Northstar system prompt. | **Task 1** — harness accepts a prompt and returns a response using a foundation model, incorporating retrieved content. |
| **`05_368563.png`** | Knowledge base `northstar-assist-kb` detail: status **Available**, service role `AmazonBedrockExecutionRoleForKnowledgeBase_pcpa3`, embeddings model `amazon.titan-embed-text-v2:0`, FLOAT32, **1024** vector dimensions, KB ID `MHJCWFFIBH`, type *Managed vector store*, data source `northstar-documents` (S3, Default chunking, Managed parser) | **Task 2** — ML-BOM component data, captured from the live resource. |
| **`16_453582.png`** | Harness creation, Tools section: gateway `northstar-assist-gateway` **on** with IAM role outbound; **Browser, Code interpreter, Remote MCP server and Custom functions all off**; Skills (0) | **Tasks 3 & 4** — the tool-scope claim behind removing 28 unused permissions. |
| **`08_390973.png`** | Gateway creation: Inbound Auth **Use IAM permissions**, Permissions **Create default role**, role name `AmazonBedrockAgentCoreGatewayDefaultServiceRole1789761291331`, target `northstar-kb` | **Task 4** — origin of the gateway service role. |
| **`27_598070.png`** | Amazon Bedrock → Guardrails: `northstar-assist-guardrail`, status **Ready** | **Task 5** — guardrail exists and is active. |
| **`28_608866.png`** | CloudWatch Overview: **6 alarms, all OK**, namespace `NorthstarAssist/Sec…`, with `NorthstarAssist-ToolCallFailure` and `NorthstarAssist-GroundingBlocked` shown as recent alarms | **Task 6** and the "automate monitoring with CloudWatch alarms" stand-out item. |

## The remaining screenshots

Labelled by position in the capture sequence rather than individually verified,
so treat these groupings as approximate:

| Range | Content |
| --- | --- |
| `01`–`04` | Cloud Resources credential panel, AWS Console home, AgentCore Knowledge Bases landing page, Create Managed KB form with the S3 data source URI |
| `06`–`07` | KB detail with the *Use with AgentCore Gateway* action, gateway target protocol and Connectors selection |
| `09`–`13` | Gateway creation details, created gateway showing **Ready** with its ARN and MCP endpoint, and the `northstar-kb` target **Ready** |
| `14`–`15` | Harness creation: model source, the Select model dialog (Anthropic → Claude Haiku 4.5 → US/Global inference profiles) |
| `17`–`19` | Harness permissions and default role, created harness showing **Ready** with harness ARN, runtime ARN and IAM role; Harness playground landing |
| `22`–`25` | Playground exchanges, including two taken while the playground's session-level system-prompt field had been overwritten with an injection payload — the guardrail still blocked both, which is the evidence behind the "guardrails survive system-prompt replacement" finding (safety-controls §1) — and the two clean re-captures with the correct system prompt restored |
| `26` | Guardrail detail page: ID `6yxbopugn44t`, **Ready**, ARN, cross-Region inference `US Guardrail v1:0`, Working draft and Version 1 |
| `29`–`34` | Teardown: harness Updating → Deleting, Gateways (0), Harnesses (0), knowledge base Deleting, Knowledge Bases empty |
| `35`–`40` | Cloud Resources budget panel reading **$25.00 left of your $25.00 budget**, and the AgentCore console showing the account emptied |
| `41` | Project brief page (`.jpg`) — the "Suggestions to Make Your Project Stand Out" list, retained for reference |

## Note on the two compromised-prompt captures

Two playground screenshots in the `22`–`25` range were taken while the
system-prompt field contained the PI-01 injection payload rather than the
Northstar prompt — pasted into the wrong field during testing. They are kept
deliberately, because both requests were **still blocked**, which is the direct
demonstration that Bedrock Guardrails are bound at invocation via
`guardrailConfig` and are not expressed in, or dependent on, the system prompt.
The clean re-captures with the correct prompt restored are alongside them. The
deployed harness was never modified; the override was session-scoped, and the
restored prompt was confirmed byte-identical (SHA-256 `59c520d5…`, 578
characters) to the one every test ran against.
