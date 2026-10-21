import subprocess
import sys
 
REPO = "https://github.com/Freamush/onze-infrastructure.git"
 
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
 
