# AutoGen and CrewAI Integration

This page is for teams running agents with AutoGen or CrewAI. It shows where to check a manifest before an agent task starts and before sensitive tools run. The [local integration example](index.md#run-a-local-verification-gate) tests that check with approved inputs and with cases that should be rejected.

## AutoGen

Put the check in your code that starts the agent or team, and in the service that runs protected tools. Pass a manifest ID along so records can be matched up, but always fetch and check the full signed record using keys and expected values that the receiving side owns.

Use the [current AgentChat guide](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/index.html) for your package and the way you start agents. Examples written for the older `pyautogen` conversation classes do not work with current AgentChat. Pin and test the version you deploy.

## CrewAI

CrewAI has a `before_kickoff` hook that runs before a crew (a group of agents) starts. Run the manifest check there before returning inputs. See [CrewAI kickoff hooks](https://docs.crewai.com/en/learn/before-and-after-kickoff-hooks) for the supported API.

A check at kickoff only tells you the state at that moment. If revocation, runtime inputs or permissions can change during the run, check again when sensitive tools run. Let failures stop the crew; do not catch them and carry on.

## Shared requirements

Keep the keys of manifest issuers and of whoever publishes revocations in your own settings, separate from incoming manifests. Always check the full signed record. In v0.1, `Ed25519Signer.sign()` returns a signature block that must be attached to the manifest; v0.2 uses COSE bytes (a standard format for signed messages).

Test that an unknown signer, a revoked ID or a mismatched runtime input stops protected work. Checking the manifest and approving the task are two separate checks. Neither framework does either one just because a manifest is attached.
