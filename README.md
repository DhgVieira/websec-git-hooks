# PRE Commit Precommit

The goal of this project is to prevent hardcoded credentials from reaching GitHub.

## Why is this so important?

Once a credential is in GitHub's history, it becomes a potential leak. It must be deactivated, new credentials created, and used properly.
But, if the credential never makes it to GitHub, then there is no need to disable it.

Also, old disabled credentials and credential-like strings hardcoded in our code may confuse new collaborators, creating the misconception that it's okay to push credentials to GitHub.

## How does it work?

SAST Precommit has a pre-commit hook configured in each MercadoLibre repository and in each developer computer. This hook parses new content that is added in every commit.
If any credentials are found, commits will be blocked until the credentials are removed or scans are skipped.

## Does it block any credential?
No, there is a list of credentials that we are analyzing on [SAST Release Process Documentation](https://furydocs.io/sast-orchestrator//guide/#/lang-es/vulns/hardcoded-credential). The list of credentials is the same in pre-commit and the `vulnerabilities` check on Release Process.
If you think that there is a credential we should add, please feel free to contact us with your feedback.

## More information
To know more about this project check the [official docs](https://furydocs.io/sast-precommit//guide/#/).

## Contact
To contact the SAST Team, please write an email to websec-sast@mercadolibre.com or join our slack channel #tech-websec.