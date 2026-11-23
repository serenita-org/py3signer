# API Reference

py3signer implements the [Ethereum Keymanager API](https://ethereum.github.io/keymanager-APIs/){:target="_blank"} for key management and a subset of the [Ethereum Remote Signing API](https://github.com/ethereum/remote-signing-api){:target="_blank"} for signing operations.

!!! danger "Experimental Software"

    This API is part of experimental software. **Do not use with production validators.**

## Base URL

All API endpoints are relative to the base URL:

```
http://localhost:8080
```

## Authentication

py3signer currently does **not** implement authentication. Bind to `127.0.0.1` (default) or use a reverse proxy with authentication for network deployments.

## Health Check

### `GET /health`

Check if the server is running and healthy.

**Response:**

```json
{
  "status": "healthy"
}
```

**Status Codes:**

- `200 OK` – Server is healthy

---

## Keymanager API

### `GET /eth/v1/keystores`

List all imported validator keys.

**Response:**

```json
{
  "data": [
    {
      "validating_pubkey": "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea7dd6c04f784f33a3e7a7b10a591ff3cb9965f31e1b91c52b97a",
      "derivation_path": "m/12381/3600/0/0/0",
      "readonly": false
    }
  ]
}
```

**Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `validating_pubkey` | string | BLS public key (48 bytes, hex-encoded with 0x prefix) |
| `derivation_path` | string | EIP-2334 derivation path |
| `readonly` | boolean | Whether the key is read-only (external keystores) |

**Status Codes:**

- `200 OK` – Successfully retrieved key list

---

### `POST /eth/v1/keystores`

Import validator keystores.

**Request Body:**

```json
{
  "keystores": [
    "{...keystore JSON...}"
  ],
  "passwords": [
    "keystore-password"
  ],
  "slashing_protection": "{...slashing protection data...}"
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `keystores` | array of strings | Yes | EIP-2335 keystore JSON strings |
| `passwords` | array of strings | Yes | Passwords for each keystore |
| `slashing_protection` | string | No | EIP-3076 slashing protection data |

!!! warning "Slashing Protection"

    py3signer **accepts but does not process** slashing protection data. The data is stored but not used for slashing prevention. See [Risks](../introduction/risks.md).

**Response:**

```json
{
  "data": [
    {
      "status": "imported",
      "message": "Successfully imported keystore with pubkey 0xa1d1..."
    }
  ]
}
```

**Status Values:**

| Value | Description |
|-------|-------------|
| `imported` | Keystore was successfully imported |
| `duplicate` | Keystore already exists |
| `error` | Import failed (see message for details) |

**Status Codes:**

- `200 OK` – Import completed (check individual results for failures)
- `400 Bad Request` – Invalid request format

---

### `DELETE /eth/v1/keystores`

Delete validator keystores.

**Request Body:**

```json
{
  "pubkeys": [
    "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea7dd6c04f784f33a3e7a7b10a591ff3cb9965f31e1b91c52b97a"
  ]
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pubkeys` | array of strings | Yes | BLS public keys to delete (with or without 0x prefix) |

**Response:**

```json
{
  "data": [
    {
      "status": "deleted",
      "message": ""
    }
  ],
  "slashing_protection": {
    "metadata": {
      "interchange_format_version": "5",
      "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
    },
    "data": [
      {
        "pubkey": "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea7dd6c04f784f33a3e7a7b10a591ff3cb9965f31e1b91c52b97a",
        "signed_blocks": [],
        "signed_attestations": []
      }
    ]
  }
}
```

**Status Values:**

| Value | Description |
|-------|-------------|
| `deleted` | Key was successfully deleted |
| `not_found` | Key was not found |
| `error` | Deletion failed (see message for details) |

!!! note "Slashing Protection Data"

    The response includes slashing protection data per EIP-3076 format. Since py3signer does not track signed messages, the `signed_blocks` and `signed_attestations` arrays are always empty.

**Status Codes:**

- `200 OK` – Deletion completed (check individual results for failures)
- `400 Bad Request` – Invalid request format

---

## Signing API

### `GET /api/v1/eth2/publicKeys`

List available BLS public keys for signing.

**Response:**

```json
[
  "0xa1d1ad0714035353258038e964ae9675dc0252ee22cea7dd6c04f784f33a3e7a7b10a591ff3cb9965f31e1b91c52b97a"
]
```

**Status Codes:**

- `200 OK` – Successfully retrieved public keys

---

### `POST /api/v1/eth2/sign/{identifier}`

Sign data with the specified validator key.

**Path Parameters:**

| Parameter | Description |
|-----------|-------------|
| `identifier` | BLS public key (with or without 0x prefix) |

**Request Body:**

```json
{
  "type": "AGGREGATION_SLOT",
  "fork_info": {
    "fork": {
      "previous_version": "0x00000000",
      "current_version": "0x00000000",
      "epoch": "0"
    },
    "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
  },
  "aggregation_slot": {
    "slot": "100"
  }
}
```

**Signing Types:**

py3signer supports the following signing domains:

| Type | Description |
|------|-------------|
| `AGGREGATION_SLOT` | Aggregation slot selection |
| `AGGREGATE_AND_PROOF` | Unversioned aggregate attestation and proof through Fulu |
| `AGGREGATE_AND_PROOF_V2` | Versioned aggregate attestation and proof |
| `ATTESTATION` | Attestation signing |
| `BLOCK` | Phase0 beacon block signing |
| `BLOCK_V2` | Versioned beacon block or block header signing |
| `DEPOSIT` | Deposit data signing |
| `RANDAO_REVEAL` | RANDAO reveal |
| `SYNC_COMMITTEE_MESSAGE` | Sync committee message |
| `SYNC_COMMITTEE_SELECTION_PROOF` | Sync committee selection proof |
| `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` | Sync committee contribution |
| `VALIDATOR_REGISTRATION` | Validator registration (MEV-Boost) |
| `VOLUNTARY_EXIT` | Voluntary exit |

**Request Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Signing domain type |
| `signingRoot` or `signing_root` | string | No | Expected SSZ signing root (32 bytes, hex) |
| `fork_info` | object | Except for deposits and registrations | Fork information for domain calculation |

py3signer derives the signing root from the request payload and its signing domain.
If a request includes a root, it must match the computed root. See
[`--network`](configuration.md#network) for the network settings. In a
`DEPOSIT` request, `deposit.genesis_fork_version` defaults to the selected
network's genesis fork version.

For `BLOCK_V2`, send `block` for Phase0 and Altair. Bellatrix through
Gloas support `block_header`. Electra, Fulu, and Gloas also support full
blocks. Use `AGGREGATE_AND_PROOF_V2` with an explicit fork for Gloas
aggregates. `BLOB_SIDECAR` requests return HTTP 400.

**Response (JSON):**

```json
{
  "signature": "0x8f3c2d1a..."
}
```

**Response (Plain Text):**

If the request includes `Accept: text/plain` header:

```
0x8f3c2d1a...
```

**Status Codes:**

- `200 OK` – Successfully signed data
- `400 Bad Request` – Invalid payload, unsupported signing request, or mismatched signing root
- `404 Not Found` – Public key not found
- `500 Internal Server Error` – Signing failure

---

## Metrics API

### `GET /metrics`

Prometheus-compatible metrics endpoint.

**Response:**

```
# HELP py3signer_sign_requests_total Total number of sign requests
# TYPE py3signer_sign_requests_total counter
py3signer_sign_requests_total 42

# HELP py3signer_keys_loaded Number of loaded keys
# TYPE py3signer_keys_loaded gauge
py3signer_keys_loaded 5
```

**Status Codes:**

- `200 OK` – Metrics retrieved successfully

See [Configuration](configuration.md) for configuring the metrics port.

---

## Error Responses

All errors follow a consistent format:

```json
{
  "status_code": 400,
  "detail": "Validation error: ..."
}
```

Common HTTP status codes:

| Code | Meaning |
|------|---------|
| `400` | Bad Request – Invalid input |
| `404` | Not Found – Key or resource not found |
| `422` | Validation Error – Schema validation failed |
| `500` | Internal Server Error – Unexpected error |

## Client Examples

### cURL

```bash
# Health check
curl http://localhost:8080/health

# List keys
curl http://localhost:8080/eth/v1/keystores

# Import keystore
curl -X POST http://localhost:8080/eth/v1/keystores \
  -H "Content-Type: application/json" \
  -d '{
    "keystores": ["{...keystore JSON...}"],
    "passwords": ["password"]
  }'

# Sign data
curl -X POST http://localhost:8080/api/v1/eth2/sign/0xa1d1... \
  -H "Content-Type: application/json" \
  -d '{
    "type": "RANDAO_REVEAL",
    "fork_info": {
      "fork": {
        "previous_version": "0x00000000",
        "current_version": "0x00000000",
        "epoch": "0"
      },
      "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
    },
    "randao_reveal": {"epoch": "3"}
  }'
```

### Python

```python
import httpx

async with httpx.AsyncClient() as client:
    # List keys
    response = await client.get("http://localhost:8080/eth/v1/keystores")
    keys = response.json()["data"]

    # Sign data
    sign_request = {
        "type": "RANDAO_REVEAL",
        "fork_info": {
            "fork": {
                "previous_version": "0x00000000",
                "current_version": "0x00000000",
                "epoch": "0",
            },
            "genesis_validators_root": "0x" + "00" * 32,
        },
        "randao_reveal": {"epoch": "3"},
    }
    response = await client.post(
        f"http://localhost:8080/api/v1/eth2/sign/{pubkey}",
        json=sign_request
    )
    signature = response.json()["signature"]
```
