# Pilot Role Mapping Guide


Use this guide to map pilot users to business functions without relying on browser extension local state.

## CSV Format

```csv
email,business_function,role,department,team,policy_group,priority
risk.analyst@bank.example,risk,Risk Analyst,Risk,Risk Ops,banking-risk,100
developer@bank.example,engineering,Backend Engineer,Engineering,Platform,engineering,100
procurement@bank.example,procurement,Procurement Manager,Operations,Procurement,procurement,100
support@bank.example,customer_support,Support Specialist,Support,Customer Ops,support,100
security@bank.example,security,Security Engineer,Security,SecOps,security,100
```

Import through:

`POST /policies/business-purpose/csv-import`

## Manual Mapping API

Create one mapping:

`POST /policies/business-purpose/mappings`

```json
{
  "email": "developer@bank.example",
  "business_function": "engineering",
  "role_name": "Backend Engineer",
  "department": "Engineering",
  "team": "Platform",
  "policy_groups": ["engineering"],
  "priority": 100,
  "source": "manual",
  "enabled": true
}
```

Test a mapping:

`POST /policies/business-purpose/mappings/test`

```json
{
  "email": "developer@bank.example",
  "claims": {},
  "extension_role_hint": "admin"
}
```

The response should show the server-side mapping and preserve `ignored_extension_role_hint`. The extension-provided role is never authoritative.

## Banking Tenant Setup

Set the tenant sector profile:

`PUT /policies/business-purpose/profile`

```json
{
  "sector": "banking",
  "sub_sector": "commercial_banking",
  "strictness": "block",
  "regulated_data_types": ["customer_account", "card_payment", "transaction", "kyc", "secret"],
  "approved_business_purposes": ["regulatory_research", "risk_analysis", "compliance_analysis", "fraud_aml_research", "software_engineering", "security_analysis", "internal_productivity"],
  "blocked_business_purposes": ["personal_use", "unrelated_consumer_research", "shopping_purchase"],
  "approved_destinations": ["internal", "approved_ai", "managed_gateway"],
  "blocked_destinations": ["public_ai_for_sensitive_data"],
  "coding_policy_id": "coding_sql_safe_mode/default",
  "sql_policy_id": "coding_sql_safe_mode/sql/default",
  "exception_policy_id": "business_purpose_exception/default"
}
```

## Unknown Users

Unknown users/functions resolve to:

- `resolved_business_function`: `unknown`
- `source`: `default_unknown`
- `confidence`: `low`
- `fallback_used`: `true`

Unknown users should produce review/restricted decisions and a `USER_ROLE_UNRESOLVED_FOR_AI_POLICY` finding when business-purpose policy is evaluated.

## Browser Extension Identity

The extension identifies the signed-in user through Hawk auth and sends telemetry with user and endpoint context. It may send hints like email or role-like local labels, but backend policy resolution uses server-side mappings only.

## Pilot Test Checklist

1. Confirm every pilot user can sign in.
2. Confirm `/users` shows every pilot user.
3. Confirm every user has a business-purpose mapping.
4. Test mapping resolution for every user email.
5. Test public business research allowed.
6. Test unrelated personal shopping blocked/warned for non-procurement roles.
7. Test procurement/facilities business purchase research allowed or reviewed.
8. Test generic coding help allowed.
9. Test production SQL/customer table blocked.
10. Test customer card/account data to public AI blocked.
11. Confirm findings include role/function, policy snapshot, decision explanation, evidence, and control mode.

