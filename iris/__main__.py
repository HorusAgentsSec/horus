"""
Entry point for the Horus Iris daemon.

Usage:
    python -m iris [--config PATH] [--install] [--test-connection]

Without flags, runs the daemon in foreground (suitable for systemd).
"""

from __future__ import annotations

import argparse
import logging
import sys
import textwrap

from iris.config import load_config


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        level=getattr(logging, level, logging.INFO),
        stream=sys.stdout,
    )


def _show_install_instructions() -> None:
    print(textwrap.dedent("""\
        ╔══════════════════════════════════════════════════════════════╗
        ║              Horus Iris — Installation Guide                 ║
        ╚══════════════════════════════════════════════════════════════╝

        1. Run the installer (requires root):

               curl -sSL https://your-horus-server/iris/install.sh | sudo bash

           Or manually:

               sudo bash /path/to/iris/install.sh

        2. Edit the config file:

               sudo nano /etc/horus/iris.yaml

           Set at minimum:
               server_url:  https://your-horus-server
               api_key:     irs_<your-api-key>
               agent_id:    <uuid-from-horus-ui>

        3. Enable and start the service:

               sudo systemctl enable --now horus-iris

        4. Check status:

               sudo systemctl status horus-iris
               sudo journalctl -u horus-iris -f

        For more information: https://docs.horus.security/iris
    """))


def _test_connection(config_path: str | None) -> bool:
    try:
        config = load_config(config_path)
        config.validate()
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"[FAIL] Config error: {exc}", file=sys.stderr)
        return False

    from iris.reporter import IrisReporter
    reporter = IrisReporter(config)
    print(f"Testing connection to {config.server_url} …")
    ok = reporter.test_connection()
    if ok:
        print("[OK]  Server reachable and credentials accepted.")
    else:
        print("[FAIL] Could not connect or credentials rejected. Check server_url and api_key.")
    return ok


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m iris",
        description="Horus Iris security agent daemon",
    )
    parser.add_argument(
        "--config",
        metavar="PATH",
        help="Path to iris.yaml config file",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Show installation instructions",
    )
    parser.add_argument(
        "--test-connection",
        action="store_true",
        dest="test_connection",
        help="Test connectivity and credentials against the Horus server",
    )
    args = parser.parse_args()

    if args.install:
        _show_install_instructions()
        sys.exit(0)

    if args.test_connection:
        ok = _test_connection(args.config)
        sys.exit(0 if ok else 1)

    # Normal daemon mode
    try:
        config = load_config(args.config)
        config.validate()
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except ValueError as exc:
        print(f"Config validation failed: {exc}", file=sys.stderr)
        print("Run with --install to see setup instructions.", file=sys.stderr)
        sys.exit(1)
    except RuntimeError as exc:
        print(f"Config parse error: {exc}", file=sys.stderr)
        sys.exit(1)

    _setup_logging(config.log_level)

    from iris.daemon import IrisDaemon
    daemon = IrisDaemon(config)
    daemon.start()


if __name__ == "__main__":
    main()
