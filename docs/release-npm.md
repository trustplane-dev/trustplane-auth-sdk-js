# npm Release Runbook

This runbook covers release readiness for the TrustPlane Auth TypeScript SDK package.

## Package

- npm package: `@trustplane/auth-sdk`
- GitHub repository: `trustplane-dev/trustplane-auth-sdk-js`
- Preview runtime: Node.js only

This preview uses `node:crypto`, so it does not claim browser or edge-runtime support.

## Version Mapping

TrustPlane release tags use a leading `v`. npm package versions do not.

- TrustPlane tag: `v0.1.0-rc.1`
- npm package version: `0.1.0-rc.1`
- npm dist-tag: `rc`

Stable releases use the `latest` dist-tag:

- TrustPlane tag: `v0.1.0`
- npm package version: `0.1.0`
- npm dist-tag: `latest`

The repository keeps `package.json` at `0.0.0` until the manual release workflow prepares a versioned release commit.

## Release Workflow

The manual workflow is `.github/workflows/release-npm.yml`.

It only runs through `workflow_dispatch`, only accepts versions matching:

```text
^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$
```

Default behavior is release-readiness only:

- `publish_package=false`
- no version commit
- no tag
- no npm publish
- no GitHub Release

The workflow verifies that the remote git tag does not already exist and that `npm view @trustplane/auth-sdk@<version>` does not already resolve before it prepares a tarball.

The workflow derives the npm dist-tag from the package version. Versions containing `-rc.` publish with dist-tag `rc`; stable versions publish with dist-tag `latest`. Never publish prerelease versions with `latest`.

## Trusted Publishing

Publishing requires npm trusted publishing with provenance from GitHub Actions.

The release workflow uses Node.js `22.14.0` and installs npm `^11.5.1` before any release checks. npm trusted publishing requires Node.js `>=22.14.0` and npm `>=11.5.1`; the workflow prints both versions and fails before publishing if either tool is too old.

Before setting `publish_package=true`, configure npm trusted publishing for:

- package: `@trustplane/auth-sdk`
- owner/repository: `trustplane-dev/trustplane-auth-sdk-js`
- workflow: `release-npm.yml`
- environment/tag policy: match the release policy chosen for the preview
- branch/ref policy: `main`
- allowed action: `npm publish`

The workflow uses:

```sh
npm publish --access public --provenance --tag <dist-tag>
```

If OIDC/trusted publishing is not available, the workflow must fail. Do not fall back to a long-lived npm token without a separate security review.

npm trusted publishing is configured manually in npm package settings before `publish_package=true`. The CLI cannot currently prove this configuration ahead of time for an unpublished package.

## No-Overwrite Rules

- Never reuse an npm version after `npm view @trustplane/auth-sdk@<version>` resolves.
- Never delete and recreate a pushed release tag for routine packaging mistakes.
- If package contents are wrong before publish, fix them before setting `publish_package=true`.
- If package contents are wrong after publish, advance to a new semver prerelease.

## Partial Failure Recovery

The workflow publishes to npm before it commits the version bump, creates the annotated tag, or pushes `main`. That keeps npm as the irreversible step and avoids publishing a git tag before the package exists.

If npm publish fails before the git push step:

1. There should be no release commit on `main` and no pushed tag.
2. Fix npm trusted publishing, package metadata, or tarball contents as needed.
3. Rerun with the same version only if `npm view @trustplane/auth-sdk@<version>` still does not resolve.
4. If package contents must change after a successful publish attempt, advance to a new version such as `v0.1.0-rc.2`.

If npm publish succeeds but the later git push fails:

1. Do not run `npm publish` again for the same version.
2. Do not delete, move, or overwrite the npm version.
3. Repair the release commit and annotated tag publication from the same workflow commit and exact package version.
4. If the tag was created locally in the failed job but not pushed, recreate the same annotated tag on the same release commit with `Medh Mesh <maintainer@trustplane.dev>` and push it.
5. Record the repair in the release notes for reviewer visibility.

If npm publish succeeded but later verification failed, do not unpublish except under npm security-policy guidance. Prefer a fixed prerelease version.

Workflow run `28151143386` failed safely before npm publish, release commit, or tag creation because npm requires an explicit dist-tag for prerelease versions. The fix is to publish `0.1.0-rc.1` with dist-tag `rc`, not `latest`.

## Verification After Publish

After publish, verify the package metadata:

```sh
npm view @trustplane/auth-sdk@0.1.0-rc.1
```

Then run a clean install/import smoke in a temporary project:

```sh
tmp=$(mktemp -d)
cd "$tmp"
npm init -y
npm install @trustplane/auth-sdk@0.1.0-rc.1
cat > smoke.mjs <<'JS'
import { HeaderAuthorization, bodySHA256 } from "@trustplane/auth-sdk";

if (HeaderAuthorization !== "Authorization") {
  throw new Error("unexpected header export");
}
if (bodySHA256("trustplane").length !== 64) {
  throw new Error("unexpected digest export");
}
JS
node smoke.mjs
```

Confirm the published tarball contains only the expected public package files: `LICENSE`, `README.md`, `SECURITY.md`, `package.json`, and `dist/*`.
