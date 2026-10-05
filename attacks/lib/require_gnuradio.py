#!/usr/bin/env python3
# Portable guard for the "wrong Python" problem.
#
# gnuradio's Python bindings are compiled C++ extensions tied to the exact
# Python build they were installed against, and there's no single path
# that's correct on every machine (Homebrew Apple Silicon /opt/homebrew,
# Intel /usr/local, Linux/conda elsewhere). Hardcoding an absolute path in a
# shebang isn't portable -- it fails with a confusing "bad interpreter"
# shell error elsewhere. So keep shebangs as `#!/usr/bin/env python3` and
# call check() before importing anything gnuradio-dependent, so a run under
# the wrong Python fails with a clear, actionable message.

import sys


def check() -> None:
    try:
        import gnuradio  # noqa: F401
    except ModuleNotFoundError:
        print("=" * 66, file=sys.stderr)
        print("ERROR: this script needs a Python build with GNU Radio installed.", file=sys.stderr)
        print(f"{sys.executable!r} does not have it.", file=sys.stderr)
        print("", file=sys.stderr)
        print("See ../PWNSAT-C3-Release/INSTALL.md for the full install guide. Quick things", file=sys.stderr)
        print("to try:", file=sys.stderr)
        print("  which python3                 # is a gnuradio-capable Python on PATH?", file=sys.stderr)
        print("  /opt/homebrew/bin/python3 -c 'import gnuradio'   # Homebrew, Apple Silicon", file=sys.stderr)
        print("  /usr/local/bin/python3 -c 'import gnuradio'      # Homebrew, Intel Mac", file=sys.stderr)
        print("If one of those works, re-run this script with that exact interpreter:", file=sys.stderr)
        print(f"  <that python3 path> {sys.argv[0]}", file=sys.stderr)
        print("=" * 66, file=sys.stderr)
        sys.exit(1)
