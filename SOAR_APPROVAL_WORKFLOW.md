# CloudSentinel SOAR approval workflow

CloudSentinel can now queue three response actions, but it deliberately does
not run them by default:

- `disable_iam_access_key` — requires `user_name`, `access_key_id`
- `block_s3_public_access` — requires `bucket_name`
- `quarantine_ec2_instance` — requires `instance_id`, `quarantine_security_group_id`, `region`

## Workflow

1. An analyst creates a request using `POST /api/soar/actions`.
2. A different approver calls `POST /api/soar/actions/{action_id}/approve`.
3. With `SOAR_EXECUTION_ENABLED=false` (the default), CloudSentinel records the
   approval but makes no AWS change.
4. Only after security review, set `SOAR_EXECUTION_ENABLED=true` and grant a
   dedicated least-privilege role the precise action permissions required.

All requests, approval identity, parameters, results, and failures are stored
in the local audit database. The response API is protected by `X-Admin-Key`.

## Example: request an IAM key containment action

```powershell
$headers = @{ 'X-Admin-Key' = '<admin-key>' }
$body = @{
  incident_id = '<incident-id>'
  action_type = 'disable_iam_access_key'
  requested_by = 'soc.analyst@example.com'
  reason = 'Unexpected key creation and new-country API activity'
  parameters = @{ user_name = 'test-user'; access_key_id = 'AKIA...' }
} | ConvertTo-Json -Depth 4
Invoke-RestMethod -Method Post http://localhost:8000/api/soar/actions -Headers $headers -ContentType 'application/json' -Body $body
```

Do not use broad AdministratorAccess for the response role. Quarantining an EC2
instance replaces its security groups, so first create and approve a dedicated
quarantine group that permits only your incident-response access path.
