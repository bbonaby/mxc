# Pull request builds

## GitHub Actions (automatic)

Every PR is validated automatically by the GitHub Actions workflows under
`.github/workflows/` (entry point: `Build.yml`). This is the primary PR
signal — it builds and tests on native Windows x64/arm64, Linux x64/arm64,
and macOS arm64 hosts in parallel.

## Azure Pipelines (optional on PRs, required on `main`)

The ADO pipeline (`MXC-PR-Build`) is the Azure version of the PR pipeline. The official
and PR Azure pipelines share the same YAML core, so running `/azp run` on a PR before
check-in is a good way to confirm your change does not inadvertently break that core.
It runs automatically on merge to `main`.

Microsoft ADO policy disables automatic PR-build runs to prevent unreviewed
code (e.g. from external forks) from executing on internal pipeline agents.
A Microsoft reviewer with repo write access can manually trigger it on a PR by
commenting `/azp run` on the pull request. Use this when you want to run the Azure
build against a change before merge.

Pipeline status:
[MXC-PR-Build](https://microsoft.visualstudio.com/Dart/_build?definitionId=192146).

## Dependency feed parity (`cargo-feed-parity`)

Every GitHub Actions Rust job (lint, the Windows/Linux/macOS builds, and the
microvm/hyperlight e2e jobs) resolves its dependency graph through the public,
anonymous-read **MxcDependencies** Azure Artifacts feed
(`.azure-pipelines/.cargo/config.public.toml`) instead of crates.io, mirroring the
network-isolated ADO PR build. The dedicated `cargo-feed-parity` job is a fast
pre-check the platform builds depend on, so a missing crate fails early with the
guidance below instead of deep in a build log.

**If a Rust job fails with an HTTP 401** (`failed to get successful HTTP response ...
401`), your PR adds a crates.io dependency that has not been cached into the feed yet.
The feed only persists a crate version when an *authenticated* client downloads it, so
the new crate must be added to the feed. How depends on where the PR branch lives:

- **In-repo branch PR** (`user/<alias>/...` pushed to this repo): a Microsoft reviewer
  with repo write access comments **`/azp run Update-Cargo-Feed`** on the PR.
- **Forked-repo PR**: someone with write access to the Mxc project in
  [dev.azure.com/shine-oss/mxc](https://dev.azure.com/shine-oss/mxc) runs the
  **Update-Cargo-Feed** pipeline manually (**Run pipeline**), setting the `prNumber`
  parameter to this PR's number, to update the feed with the new dependencies the PR
  introduces.

Then re-run the failed Rust job; it should now pass.