# Release Procedure

The repository contains three independently versioned Python packages. A repository change does not imply that every package receives a new version.

## Version policy

Use semantic version numbers:

- MAJOR: incompatible CLI, output-schema, or supported-input changes;
- MINOR: backward-compatible features or new report fields;
- PATCH: backward-compatible fixes, security hardening, and documentation corrections shipped with a package.

Package names and tag prefixes:

| Package | Metadata path | Tag format |
| --- | --- | --- |
| `eval-unpacker` | `tools/eval-unpacker/pyproject.toml` | `eval-unpacker-vX.Y.Z` |
| `pcap-quick-profiler` | `tools/pcap-profiler/pyproject.toml` | `pcap-quick-profiler-vX.Y.Z` |
| `winlog-triage` | `tools/winlog-triage/pyproject.toml` | `winlog-triage-vX.Y.Z` |

GitHub Releases are the current distribution channel. PyPI publication is not enabled. Adding a registry publisher requires a separately reviewed trusted-publishing workflow with environment protection and no long-lived API token.

## Release checklist

1. Update the target package version in `pyproject.toml` and, where exposed, `__version__`.
2. Move relevant entries from `[Unreleased]` in `CHANGELOG.md` into a dated version section.
3. Verify documented commands against installed `--help` output.
4. Open a pull request and require `Required repository checks` to pass on an up-to-date branch.
5. Build both the wheel and source distribution for every package being released.
6. Inspect both archives for required code/resources and forbidden reports, captures, caches, credentials, or package metadata.
7. Install each wheel into a clean environment and run every console and module entry point.
8. For PCAP changes, run the deterministic TShark integration test.
9. Confirm strict dependency auditing and secret scanning pass.
10. Merge the release-preparation pull request before tagging.
11. Check out the updated `main`, record the exact merged commit SHA, and verify `Required repository checks` succeeded for that SHA before creating a tag.

Do not create a release when tests, lint, builds, artifact inspection, installed smoke tests, security scans, documentation, or the aggregate required check are incomplete or failing.

## Verify and export the release commit

After the release-preparation pull request is merged, update `main`, require a completely clean index and worktree, and record the exact merged commit:

```bash
git switch main
git pull --ff-only origin main
test -z "$(git status --porcelain)"
release_sha="$(git rev-parse HEAD)"
```

Verify exactly one completed, successful `push` run of the repository's `repository-ci.yml` workflow exists for that exact commit. Scoping by workflow file and event prevents an unrelated check or integration from satisfying the release gate; requiring exactly one result fails closed on ambiguous matches.

```bash
run_gate="$(gh run list \
  --repo Love2150/security-tools \
  --workflow repository-ci.yml \
  --commit "$release_sha" \
  --event push \
  --limit 2 \
  --json headSha,status,conclusion \
  --jq 'if length == 1 then .[0] | [.headSha, .status, .conclusion] | @tsv else "invalid-count" end')"
expected_gate="$(printf '%s\tcompleted\tsuccess' "$release_sha")"
test "$run_gate" = "$expected_gate"
```

Export source directly from the verified Git object rather than building from mutable working-tree files. This cryptographically binds the build input to `release_sha`:

```bash
release_root="$(mktemp -d)"
mkdir -p "$release_root/source" "$release_root/artifacts"/{eval,pcap,winlog}
git archive --format=tar "$release_sha" | tar -xf - -C "$release_root/source"
```

## Build commands

```bash
uv build "$release_root/source/tools/eval-unpacker" --out-dir "$release_root/artifacts/eval"
uv build "$release_root/source/tools/pcap-profiler" --out-dir "$release_root/artifacts/pcap"
uv build "$release_root/source/tools/winlog-triage" --out-dir "$release_root/artifacts/winlog"
```

Generate a release-specific checksum file from inside only the target package's artifact directory so entries use portable relative filenames. For example:

```bash
(cd "$release_root/artifacts/eval" && sha256sum -- *.whl *.tar.gz > SHA256SUMS)
(cd "$release_root/artifacts/pcap" && sha256sum -- *.whl *.tar.gz > SHA256SUMS)
(cd "$release_root/artifacts/winlog" && sha256sum -- *.whl *.tar.gz > SHA256SUMS)
```

Run only the checksum command for the package being released. Immediately before tagging and publishing, ensure the checkout is still the verified commit and remains clean:

```bash
test "$(git rev-parse HEAD)" = "$release_sha"
test -z "$(git status --porcelain)"
```

Create an annotated tag from `release_sha`, using the applicable package tag format. Push the tag, then create a GitHub Release whose title and notes match the changelog. Attach that package's wheel, source distribution, and its own `SHA256SUMS`. If several packages are intentionally released together, create distinct package tags, checksum files, and releases so version histories remain unambiguous.

## Verification after publishing

Read back the tag target and GitHub Release. Download the published artifacts, verify SHA-256 checksums, install the downloaded wheel in a clean environment, and repeat the CLI smoke test. A successful upload alone is not a verified release.
