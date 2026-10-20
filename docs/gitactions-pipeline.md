## CI/CD: GitHub Actions

Every change to the infrastructure goes through an automated quality gate before it reaches `main`. The pipelines in [`.github/workflows`](.github/workflows) enforce security and cost control at the pull request stage, catching problems before they ever reach Azure.

### PR-based workflow
`main` is protected, so direct pushes are not allowed. Every Terraform change must be submitted as a pull request and pass all required checks before it can be merged and deployed. This keeps Git as the single source of truth for the infrastructure and makes every change reviewed, validated and traceable.

### Checks
The pipeline consists of two workflows and the Infracost GitHub App:

- **`gitleaks.yml`: secret scanning.** Scans the entire repository for leaked credentials such as keys, tokens and passwords, so no secret ever makes it into version control.
- **`terraform-pr.yml`: IaC validation and security.** Runs `terraform fmt` and `terraform validate` to enforce formatting and catch configuration errors. It then runs **Checkov** to detect security misconfigurations against industry benchmarks before deployment.
- **Infracost: FinOps.** Estimates the cost impact of every pull request and posts it as a PR comment, so the cost of a change is known before it is merged.
<img width="840" height="866" alt="image" src="https://github.com/user-attachments/assets/c2f65181-e335-448a-974a-d41a17f3019e" />

In a real production environment PRs should be reviewed by another collaborator. 
