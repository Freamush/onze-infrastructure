# Drift check: terraform plan against the code on main.
# Exit codes of plan -detailed-exitcode: 0 = no drift, 2 = drift, 1 = error.
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = "https://github.com/Freamush/onze-infrastructure.git"

# Terraform only knows the VM metadata endpoint (169.254.169.254) for managed
# identity. Container Apps exposes the identity on IDENTITY_ENDPOINT instead,
# which also needs the X-IDENTITY-HEADER. This small local proxy translates
# Terraform's requests to the Container Apps endpoint and caches the tokens.
tokens = {}
lock = threading.Lock()


def get_token(resource):
    with lock:
        cached = tokens.get(resource)
        if cached and int(cached["expires_on"]) - time.time() > 300:
            return cached
        params = urllib.parse.urlencode({
            "api-version": "2019-08-01",
            "resource": resource,
            "client_id": os.environ["ARM_CLIENT_ID"],
        })
        request = urllib.request.Request(
            f"{os.environ['IDENTITY_ENDPOINT']}?{params}",
            headers={"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            tokens[resource] = json.load(response)
        return tokens[resource]


class IdentityProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            resource = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)["resource"][0]
            token = dict(get_token(resource))
            # Terraform expects expires_in, Container Apps returns expires_on
            token["expires_in"] = str(int(token["expires_on"]) - int(time.time()))
            status, body = 200, json.dumps(token).encode()
        except Exception as error:  # report instead of dropping the connection
            print(f"identity proxy error: {error!r}", file=sys.stderr, flush=True)
            status, body = 500, json.dumps({"error": str(error)}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


proxy = ThreadingHTTPServer(("127.0.0.1", 0), IdentityProxy)
threading.Thread(target=proxy.serve_forever, daemon=True).start()
os.environ["ARM_MSI_ENDPOINT"] = f"http://127.0.0.1:{proxy.server_port}/metadata/identity/oauth2/token"


subprocess.run(["git", "clone", "--depth", "1", REPO, "repo"], check=True)
subprocess.run(["terraform", "init", "-input=false", "-no-color"], cwd="repo/infra", check=True)

# Output goes straight to the log, so progress is visible while plan runs
plan = subprocess.run(
    ["terraform", "plan", "-input=false", "-lock=false", "-no-color", "-detailed-exitcode"],
    cwd="repo/infra", check=False,
)

if plan.returncode == 0:
    print("DRIFT_CHECK_RESULT=NO_DRIFT", flush=True)
elif plan.returncode == 2:
    print("DRIFT_CHECK_RESULT=DRIFT_DETECTED", flush=True)
else:
    print("DRIFT_CHECK_RESULT=ERROR", flush=True)
    sys.exit(1)
