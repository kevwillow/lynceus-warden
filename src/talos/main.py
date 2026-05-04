"""Application entrypoint: parse args, wire components, and start the poll loop."""

import sys

from .poller import main

if __name__ == "__main__":
    sys.exit(main())
