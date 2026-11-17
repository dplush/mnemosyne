# Docker Hub previews from the personal fork

This optional workflow is for `dplush/mnemosyne` and publishes community preview builds to `ddplush/mnemosyne-mcp`. It is separate from the upstream release workflow and does not change the project's release configuration. No workflow, credentials, repository settings or publication are activated by adding these files.

## Default behavior

`Docker Hub preview (manual)` only responds to `workflow_dispatch`. Its default `publish=false` builds and runs the existing MCP and full Docker deployment acceptance on native Linux AMD64 and ARM64 runners. It needs no Docker Hub token in this mode and does not upload images or image artifacts. Model downloads, runtime inference, persistence, authentication, backup/restore and Caddy HTTPS are part of the existing suite.

The source is the selected workflow ref resolved by GitHub to the full `github.sha`. Both jobs explicitly check out that SHA. The selected ref must contain the Docker deployment and preview workflow/helpers/tests. There is no arbitrary repository or release-tag input. The workflow is skipped in the upstream repository and all repositories other than the named personal fork.

## Prepare the fork

1. Review and transfer the prepared branch into `dplush/mnemosyne`; the workflow must exist on its default branch for GitHub to offer manual dispatch. This preparation does not push or merge that branch.
2. Enable GitHub Actions in the fork if needed. The account/repository must have access to `ubuntu-24.04` and `ubuntu-24.04-arm`; do not replace the ARM64 acceptance job with an untested cross-build.
3. First run the workflow on the intended branch with **Publish tested preview images unchecked**. Confirm both architecture jobs executed and passed.

A future tests-only dispatch can use:

```bash
gh workflow run docker-preview.yml --repo dplush/mnemosyne --ref YOUR_REVIEWED_BRANCH -f publish=false
```

This command starts builds and tests; it is an operator instruction, not a step executed during preparation. No workflow run has been started as part of this change.

## Publication setup for a later, separately authorized step

- Create the Docker Hub repository `ddplush/mnemosyne-mcp` with the desired visibility. Describe it as an unofficial/community preview and link to the fork and upstream project. Preserve the included license/copyright material.
- Create the GitHub environment `dockerhub-preview`. Configure an approval rule if supported by your account/plan, plus appropriate deployment branch restrictions. Merely naming an environment in YAML does not configure protection.
- Store a Docker Hub personal access token with push access as **environment secret** `DOCKERHUB_TOKEN` in that environment. Keep the token out of chat, YAML and committed `.env` files. The username `ddplush` is public workflow configuration, not a secret. Use the least token permissions required for pushing; deletion is not needed.
- Only when ready to enable publication, set the fork's repository variable `MNEMOSYNE_DOCKERHUB_PREVIEW_ENABLED=true`.
- A publishing run also requires explicitly selecting `publish=true`. Leaving either switch off prevents the publish job and Docker Hub login. Keep the activation variable absent/false during preparation.

A publishing run builds and tests both architectures first, then saves only the tested images as run-scoped artifacts with one-day retention. A separate job loads both images, verifies their platform and fork/source SHA labels, and only then logs in. It pushes those exact images without rebuilding them, then assembles the multi-platform manifest from the pushed repository digests. The build/test jobs receive no Docker Hub credentials. If environment approval outlasts artifact retention, rerun the complete workflow rather than attempting to publish expired artifacts. Publication fails if either architecture, an artifact, or its identity validation fails.

## Tags and source identity

For full source SHA `<sha>`:

```text
ddplush/mnemosyne-mcp:preview-sha-<sha>
ddplush/mnemosyne-mcp:preview-sha-<sha>-amd64
ddplush/mnemosyne-mcp:preview-sha-<sha>-arm64
```

There is no `latest`, version/release tag, automatic push trigger or automatic tag trigger. Image source/revision labels identify the fork and commit; the description labels the build as an unofficial community preview. The run summary records the final manifest inspection.

Commit tags identify source but do not make Docker Hub tags immutable. Re-running the same commit may replace its preview tags. Pin `ddplush/mnemosyne-mcp@sha256:...` for an immutable image selection. A failed publishing run can leave an architecture-specific tag behind before the combined manifest is created; success requires the final manifest step as well as both native tests.

## Verification of this preparation

Offline tests exercise metadata/target validation, platform/source checks, pushed-digest selection, workflow gates and the actual pre-login shell gate with fixture images. Actionlint validates the workflow syntax. These tests do not replace a native workflow run: this preparation does not execute GitHub Actions, start real containers, authenticate to Docker Hub or publish images.

References: [Docker Hub authentication with GitHub Actions](https://docs.docker.com/build/ci/github-actions/), [passing single-platform images between jobs](https://docs.docker.com/build/ci/github-actions/share-image-jobs/).
