# Release checklist

Use this checklist when a maintainer chooses to publish a version. Repository upload and a tagged release are separate operations.

- Review the exact diff, included files, license and third-party notices.
- Run the quickstart and evaluation suite on the release commit; record failures, skips and runtime versions.
- Confirm the hosted CI result for that commit. A local pass does not establish hosted CI success.
- Check README links and diagram rendering; confirm installation instructions match the package layout.
- Exclude caches, credentials, runtime state, private captures and unlicensed assets from tracked files and archives.
- Update the changelog with the intended version and concrete changes.
- After release authorization, create the chosen tag and use the repository release workflow. Inspect the resulting archive and release page.

Do not claim full Web, desktop or mobile acceptance from controller smoke tests. Browser/device integration needs its own environment and evidence.
