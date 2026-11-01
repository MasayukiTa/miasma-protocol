#!/usr/bin/env python3
"""Check that every Rust integration test named in the CI workflow exists.

The CI core test list in .github/workflows/ci.yml runs selected integration
tests by name with `cargo test ... --test <name>`. A test file that is meant to
run by name in CI must be registered there, and a name registered in CI must
point at a real test file. This check keeps the two in step: it collects every
`--test <name>` used on a cargo test line and fails if any of them has no
matching crates/*/tests/<name>.rs file.

Exit code 0 when the manifest is consistent, 1 otherwise.
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW = os.path.join(ROOT, ".github", "workflows", "ci.yml")


def cargo_test_names(text):
    names = set()
    for raw in text.splitlines():
        # Strip trailing YAML comments so prose in a `#` comment never looks
        # like a cargo flag.
        line = raw.split("#", 1)[0]
        if "--test" not in line:
            continue
        # Only count --test flags that belong to cargo test invocations.
        # Node's `node --test` is skipped because it never pairs with cargo.
        if "node" in line and "cargo test" not in line:
            continue
        for name in re.findall(r"--test\s+([A-Za-z0-9_]+)", line):
            names.add(name)
    return names


def test_file_stems(root):
    stems = set()
    for path in glob.glob(os.path.join(root, "crates", "*", "tests", "*.rs")):
        stems.add(os.path.splitext(os.path.basename(path))[0])
    return stems


def main():
    with open(WORKFLOW, encoding="utf-8") as handle:
        text = handle.read()
    named = cargo_test_names(text)
    stems = test_file_stems(ROOT)
    missing = sorted(name for name in named if name not in stems)
    if missing:
        sys.stderr.write(
            "CI names these tests with --test but no crates/*/tests/<name>.rs "
            "file exists:\n"
        )
        for name in missing:
            sys.stderr.write("  - %s\n" % name)
        return 1
    print("CI test manifest is consistent (%d named tests checked)." % len(named))
    return 0


if __name__ == "__main__":
    sys.exit(main())
