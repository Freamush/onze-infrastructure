# Drift Detection
Every 30 minutes a container in Azure compares the live environment with the Terraform code on main. If someone changes a resource manually in the portal, the change is detected and an alert is sent.

**How a check works**
The job starts the drift-checker container from ACR.
check.py clones main and runs terraform init and terraform plan -detailed-exitcode -lock=false.

The result is written to the log as one line:
    DRIFT_CHECK_RESULT=NO_DRIFT: Azure matches the code
    DRIFT_CHECK_RESULT=DRIFT_DETECTED: the full plan is printed above this line
    DRIFT_CHECK_RESULT=ERROR: the check could not finish

