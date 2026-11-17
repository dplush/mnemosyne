# Docker Hub previews from the personal fork

This optional workflow is for `dplush/mnemosyne` and publishes community preview builds to `ddplush/mnemosyne-mcp`. It is separate from the upstream release workflow and does not change the project's release configuration. No workflow, credentials, repository settings or publication are activated by adding these files.

## Default behavior

`Docker Hub preview (manual)` only responds to `workflow_dispatch`. Its default `publish=false` builds and runs the existing MCP and full Docker deployment acceptance on native Linux AMD64 and ARM64 runners. It needs no Docker Hub token in this mode and does not upload images or image artifacts. Model downloads, runtime inference, persistence, authentication, backup/restore and Caddy HTTPS are part of the existing suite.

With `source_tag` empty, the source is the selected workflow ref resolved by GitHub to the full `github.sha`. With a stable tag such as `v4.0.0`, a resolver fetches that tag only from `mnemosyne-oss/mnemosyne`, dereferences annotated tags and verifies the package version. Both architecture jobs then fetch the same resolved commit SHA. The selected workflow ref supplies the maintained Docker recipe, dependency constraints, helpers and acceptance tests; the release supplies the unchanged package and packaging files. There is no arbitrary source repository input. The workflow is skipped in the upstream repository and all repositories other than the named personal fork.

## Prepare the fork

1. Review and transfer the prepared branch into `dplush/mnemosyne`; the workflow must exist on its default branch for GitHub to offer manual dispatch. This preparation does not push or merge that branch.
2. Enable GitHub Actions in the fork if needed. The account/repository must have access to `ubuntu-24.04` and `ubuntu-24.04-arm`; do not replace the ARM64 acceptance job with an untested cross-build.
3. First run the workflow on the intended branch with **Publish tested preview images unchecked**. Confirm both architecture jobs executed and passed.

A future tests-only dispatch can use:

```bash
gh workflow run docker-preview.yml --repo dplush/mnemosyne --ref YOUR_REVIEWED_BRANCH -f publish=false
```

To test a tagged upstream version using the recipe on your reviewed fork branch:

```bash
gh workflow run docker-preview.yml --repo dplush/mnemosyne --ref YOUR_REVIEWED_BRANCH \
  -f source_tag=v4.0.0 -f publish=false
```

Keep `--ref` on the branch containing the new workflow, not the old upstream tag. `source_tag` selects the release code separately. Stable `vMAJOR.MINOR.PATCH` tags are supported; a missing tag or a tag/package version mismatch fails before building. The old release's Dockerfile is deliberately not used: it can install an unpinned PyPI version instead of the tagged code. A release that cannot pass the current deployment acceptance is not published or silently patched.

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

When `source_tag=v4.0.0`, a separately authorized publishing run instead targets `4.0.0`, `4.0.0-amd64` and `4.0.0-arm64` in the same personal Docker Hub repository. These remain unofficial community images, not upstream releases. There is no `latest`, automatic push trigger or automatic tag trigger.

Image source/revision labels identify the actual source repository and commit. `org.opencontainers.image.version` and the installed wheel must match the selected release version. `io.mnemosyne.community.recipe.revision` separately records the fork commit supplying the Docker recipe. Pre-login checks verify both release and recipe identity. The run summary records source/recipe commits and the final manifest inspection.

Commit tags identify source but do not make Docker Hub tags immutable. Re-running the same source may replace its preview or version tags, including when the recipe changes. Pin `ddplush/mnemosyne-mcp@sha256:...` for an immutable image selection. A failed publishing run can leave an architecture-specific tag behind before the combined manifest is created; success requires the final manifest step as well as both native tests.

## Verification of this preparation

Offline tests exercise lightweight/annotated tag resolution using local Git repositories, package-version checks, isolated context assembly, metadata/target validation, platform/source/recipe checks, pushed-digest selection, workflow gates and the actual pre-login shell gate with fixture images. Actionlint validates the workflow syntax. These tests do not replace a native workflow run. A `publish=false` dispatch builds and tests containers but does not authenticate to Docker Hub or publish images.

References: [Docker Hub authentication with GitHub Actions](https://docs.docker.com/build/ci/github-actions/), [passing single-platform images between jobs](https://docs.docker.com/build/ci/github-actions/share-image-jobs/).
