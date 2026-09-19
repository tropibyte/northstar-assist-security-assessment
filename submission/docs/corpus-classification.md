# Northstar Assist - Knowledge Base Corpus Classification

Documents scanned: **30**  
Scanner: `submission/scripts/scan_corpus.py` (deterministic regex rules, no model calls)

Every document below is retrievable by the agent through the gateway's
`Retrieve` tool. Retrieved chunks are placed directly into the model's
context window **without passing through the input guardrail**, so the
classification here defines the blast radius of a successful retrieval.

## Classification summary

| Tier | Documents |
| --- | --- |
| RESTRICTED | 1 |
| CONFIDENTIAL | 12 |
| INTERNAL | 17 |

## Detections by rule

| Rule | Occurrences |
| --- | --- |
| `employee_id` | 64 |
| `internal_email` | 44 |
| `customer_id` | 33 |
| `external_email` | 30 |
| `ticket_id` | 18 |
| `opportunity_id` | 15 |
| `us_phone` | 7 |
| `ec2_instance_id` | 6 |
| `aws_account_id` | 3 |
| `password_literal` | 2 |
| `api_bearer_token` | 1 |
| `generic_bearer` | 1 |

## Per-document detail

| Document | Format | Tier | Detections |
| --- | --- | --- | --- |
| `csv/aws_infrastructure_inventory.csv` | csv | CONFIDENTIAL | ec2_instance_id x6 - cols: monthly_cost |
| `csv/customer_accounts.csv` | csv | CONFIDENTIAL | external_email x15, customer_id x15 - cols: monthly_revenue |
| `csv/employee_directory.csv` | csv | CONFIDENTIAL | internal_email x25, employee_id x41 |
| `csv/sales_pipeline.csv` | csv | CONFIDENTIAL | external_email x15, opportunity_id x15 - cols: deal_size, probability |
| `csv/support_tickets.csv` | csv | INTERNAL | customer_id x18, ticket_id x18 |
| `docx/disaster_recovery_plan.docx` | docx | INTERNAL | us_phone x5 |
| `docx/product_requirements_document.docx` | docx | INTERNAL | - |
| `docx/quarterly_business_review.docx` | docx | INTERNAL | - |
| `docx/security_policy.docx` | docx | CONFIDENTIAL | internal_email x2, us_phone x1 |
| `docx/sow_template.docx` | docx | INTERNAL | - |
| `html/api_authentication_guide.html` | html | RESTRICTED | api_bearer_token x1, generic_bearer x1, internal_email x1 |
| `html/aws_architecture_documentation.html` | html | CONFIDENTIAL | aws_account_id x3 |
| `html/company_policies_handbook.html` | html | CONFIDENTIAL | internal_email x6, us_phone x1 |
| `html/product_features_overview.html` | html | CONFIDENTIAL | internal_email x1 |
| `html/troubleshooting_guide.html` | html | CONFIDENTIAL | internal_email x2 |
| `pdf/api_best_practices.pdf` | pdf | INTERNAL | - |
| `pdf/compliance_overview.pdf` | pdf | INTERNAL | - |
| `pdf/customer_success_playbook.pdf` | pdf | INTERNAL | - |
| `pdf/data_governance_policy.pdf` | pdf | INTERNAL | - |
| `pdf/service_level_agreement.pdf` | pdf | INTERNAL | - |
| `txt/company_announcement_q3_kickoff.txt` | txt | INTERNAL | - |
| `txt/engineering_team_meeting_notes_2023_06_15.txt` | txt | INTERNAL | - |
| `txt/incident_report_2023_06_03.txt` | txt | INTERNAL | - |
| `txt/onboarding_checklist_engineering.txt` | txt | CONFIDENTIAL | internal_email x6 |
| `txt/release_notes_v2.5.0.txt` | txt | CONFIDENTIAL | internal_email x1 |
| `xlsx/budget_tracking_q3_2023.xlsx` | xlsx | INTERNAL | - |
| `xlsx/employee_training_records.xlsx` | xlsx | INTERNAL | employee_id x23 |
| `xlsx/okr_tracking_q3_2023.xlsx` | xlsx | INTERNAL | - |
| `xlsx/project_timeline_q3_2023.xlsx` | xlsx | INTERNAL | - |
| `xlsx/vendor_management.xlsx` | xlsx | CONFIDENTIAL | password_literal x2 |
