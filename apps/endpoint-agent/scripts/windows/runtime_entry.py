"""PyInstaller entry point that preserves package import semantics."""

from hawk_endpoint_agent.__main__ import main


if __name__ == "__main__":
    raise SystemExit(main())
