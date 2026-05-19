import sys
import os
import logging
import argparse
import speakeasy

def main():
    parser = argparse.ArgumentParser(description="Emulate a PE file using Speakeasy")
    parser.add_argument("file", help="Path of PE file to emulate")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (DEBUG) logging")
    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Initializing Speakeasy emulator...")
    se = speakeasy.Speakeasy()

    print(f"[*] Loading module: {args.file}...")
    module = se.load_module(path=args.file)

    print(f"[*] Running module entry point...")
    se.run_module(module)
    print(f"[*] Emulation finished successfully!")

if __name__ == "__main__":
    main()