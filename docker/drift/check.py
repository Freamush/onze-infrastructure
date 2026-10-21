import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

REPO = "https://github.com/Freamush/onze-infrastructure.git"


# Terraform only knows the VM metadata endpoint (169.254.169.254) for managed
# identity. Container Apps exposes the identity on IDENTITY_ENDPOINT instead,
# which also needs the X-IDENTITY-HEADER. This small local proxy translates
# Terraform's requests to the Container Apps endpoint.
class IdentityProxy(BaseHTTPRequestHandler):
    def do_GET(self):
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        params = urllib.parse.urlencode({
            "api-version": "2019-08-01",
            "resource": query["resource"][0],
            "client_id": os.environ["ARM_CLIENT_ID"],
        })
        request = urllib.request.Request(
            f"{os.environ['IDENTITY_ENDPOINT']}?{params}",
            headers={"X-IDENTITY-HEADER": os.environ["IDENTITY_HEADER"]},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            token = json.load(response)
        # Terraform expects expires_in, Container Apps returns expires_on
        token["expires_in"] = str(int(token["expires_on"]) - int(time.time()))
        body = json.dumps(token).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


proxy = HTTPServer(("127.0.0.1", 0), IdentityProxy)
threading.Thread(target=proxy.serve_forever, daemon=True).start()
os.environ["ARM_MSI_ENDPOINT"] = f"http://127.0.0.1:{proxy.server_port}/metadata/identity/oauth2/token"


subprocess.run(["git", "clone", "--depth", "1", REPO, "repo"], check=True)
subprocess.run(["terraform", "init", "-input=false"], cwd="repo/infra", check=True)

plan = subprocess.run(
    ["terraform", "plan", "-input=false", "-lock=false", "-no-color", "-detailed-exitcode"],
    cwd="repo/infra", capture_output=True, text=True, check=False,
)

if plan.returncode == 0:
    print("DRIFT_CHECK_RESULT=NO_DRIFT")
elif plan.returncode == 2:
    print(plan.stdout)
    print("DRIFT_CHECK_RESULT=DRIFT_DETECTED")
else:
    print(plan.stderr)
    print("DRIFT_CHECK_RESULT=ERROR")
    sys.exit(1)