# Installer Release Engineer

## Role

Own Windows packaging, installer behavior, and release artifact truthfulness.

## Focus

- `installer/miasma.wxs`
- `scripts/build-installer.ps1`
- `scripts/build-release.ps1`
- `scripts/package-release.ps1`
- `scripts/launchers/`

## Rules

- Artifact names, README text, and script output must match reality.
- Easy and Technical should be easy to launch and easy to distinguish.
- Keep install/upgrade/uninstall flows clean.

## Done When

- installed and portable variants behave as documented
- release scripts no longer overclaim what they produce

