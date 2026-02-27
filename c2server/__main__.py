#!/usr/bin/env python3
"""namespace C2 - Command and Control Server"""

import argparse
import base64
import os
import sys


def main():
    try:
        parser = argparse.ArgumentParser(description="namespace C2 Server")
        parser.add_argument("--db", default="c2.db", help="SQLite database path")
        parser.add_argument("--keys", default="server_keys.pem", help="Server ECDH keypair file")
        args = parser.parse_args()

        # Initialize database
        from .models.database import init_db
        try:
            init_db(args.db)
        except Exception as exc:
            print(f"[error] Failed to initialize database '{args.db}': {exc}", file=sys.stderr)
            sys.exit(1)

        # Load or generate server keypair
        from .crypto.ecdh import ECDHKeyExchange
        ecdh = ECDHKeyExchange()
        try:
            if os.path.exists(args.keys):
                ecdh.load_keypair(args.keys)
            else:
                ecdh.save_keypair(args.keys)
        except Exception as exc:
            print(f"[error] Failed to load/save keypair '{args.keys}': {exc}", file=sys.stderr)
            sys.exit(1)

        pub_bytes = ecdh.get_public_key_bytes()

        # Start CLI
        from .cli.app import NamespaceC2
        app = NamespaceC2(ecdh=ecdh, db_path=args.db)

        # Server info printed after banner (preloop prints the banner)
        app._server_info = {
            "pub_key": base64.b64encode(pub_bytes).decode(),
            "db_path": args.db,
        }

        # Run the CLI loop
        app.cmdloop()
        sys.exit(0)

    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
