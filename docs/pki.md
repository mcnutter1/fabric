# PKI & TLS Inspection

The management plane is the certificate authority for the entire fabric. It runs a
three-tier hierarchy and mints every identity used for mTLS between nodes, client
enrollment, and inline TLS inspection.

## Hierarchy

```
Fabric Root CA (RSA-4096, offline-capable, long-lived)
├── Infrastructure CA (RSA)      -> node identity certs (mTLS between agent & manager)
├── Endpoint CA (RSA)            -> client/endpoint certs (device identity)
└── Inspection (MITM) CA (RSA)   -> issued to egress nodes to mint leaf certs at line rate
```

* **Root CA** — self-signed, RSA-4096. Its private key is encrypted at rest with a
  Fernet key derived from `FABRIC_PKI_PASSPHRASE` (`sha256(passphrase)` → urlsafe
  base64). The root only ever signs the three intermediates.
* **Intermediates** — RSA, signed by the root, each scoped to a single purpose so a
  compromise is contained and independently revocable.
* **Leaves** — EC P-256 (fast to generate/verify), signed by the relevant
  intermediate.

Bootstrap happens automatically on first start (`PKIService.bootstrap()`), or
explicitly via `POST /api/v1/pki/bootstrap`. Status is visible at
`GET /api/v1/pki/status` and in the console **PKI** view.

## Certificate lifecycle

| Purpose            | Issuer          | Key    | Delivered via                     |
|--------------------|-----------------|--------|-----------------------------------|
| Node identity      | Infrastructure  | EC     | `/node/enroll` response           |
| Endpoint identity  | Endpoint CA     | EC     | endpoint config bundle            |
| Inspection leaves  | MITM CA         | EC     | minted on the egress node itself  |

Node certs carry SANs for the node name, its fabric address, and the public
endpoint host. Endpoints receive a full trust bundle (root + relevant chain) so
they can validate the fabric and, when inspection is enabled, the MITM CA.

## TLS inspection (MITM)

Inline decryption happens on **egress** nodes only:

1. On enrollment/refresh an egress agent calls `GET /node/pki/mitm` and receives
   the MITM intermediate **cert + private key** (`ca_cert_pem`, `ca_key_pem`).
   This route is authorization-gated to egress-role nodes and audited.
2. The agent loads them into `TLSInspector`. For each observed SNI it mints a
   short-lived (24h) EC leaf signed by the MITM CA, cached per-hostname.
3. A TLS-terminating proxy presents that leaf to the client. Because the endpoint
   trust bundle includes the MITM CA, the session validates and the proxy can
   classify/inspect the plaintext, then re-originate TLS to the true upstream.

Policy decides *whether* to inspect: a rule with action `inspect` marks matching
flows for decryption; everything else is passed through (SNI/metadata only). This
keeps sensitive categories (e.g. `finance`, `health`) exempt from decryption by
policy while still allowing category enforcement via SNI.

### Trust distribution

* Endpoints: the MITM CA is included in the endpoint trust bundle only when the
  applicable policy enables inspection for that user/device.
* Managed OSes: push the MITM CA to the system/browser trust store via MDM.

## Revocation & rotation

* Node/endpoint certs are short-lived; rotation is a re-issue on the next
  enrollment/refresh. Revoked certs are flagged in the `certificates` table and
  surfaced in the console.
* Rotating an intermediate re-issues all leaves under it on next contact.
* Rotating the **root** is a planned migration: stand up a new root, cross-sign,
  re-issue intermediates, then retire the old root once all nodes/endpoints have
  refreshed their bundles.

## Secrets

| Secret                     | Where                          | Notes                            |
|----------------------------|--------------------------------|----------------------------------|
| `FABRIC_PKI_PASSPHRASE`    | management env                 | derives the CA-key encryption key|
| CA private keys            | DB (`encrypted_key`), Fernet   | never leave the manager except MITM to egress |
| Node token                 | agent `state.json` (0600)      | bearer for `/node/*`             |

Losing `FABRIC_PKI_PASSPHRASE` means the CA keys cannot be decrypted — back it up
in your secrets manager alongside a DB backup.
