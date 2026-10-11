"""Thin launcher so `python main.py` works from the project root."""

from cybertrap.main import main

if __name__ == "__main__":
    raise SystemExit(main())
