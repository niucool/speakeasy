"""
sptest.py  Speakeasy Python test runner for log comparison with C++ port.

Usage:
  python sptest.py -v d:/path/to/sample.exe          # verbose to stderr
  python sptest.py -v -l py.log d:/path/to/sample.exe  # verbose to file

Compare with C++ logs:
  .\\build\\Debug\\speakeasy-cli.exe -v -t d:\\path\\to\\sample.exe 2> cpp.log
"""

import sys
import os
import logging
import argparse
import speakeasy


def main():
    parser = argparse.ArgumentParser(description="Emulate a PE using Speakeasy (Python)")
    parser.add_argument("file", help="Path of PE file to emulate")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (DEBUG) logging")
    parser.add_argument("-l", "--logfile", type=str, default=None, help="Write log to file instead of stderr")
    parser.add_argument("-r", "--report", type=str, default=None, help="Write JSON report to file")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Configure logging  format matches C++ CleanFormatter style for easy diff
    log_fmt = "%(asctime)s %(levelname)-5s [%(thread)d] %(name)s: %(message)s"
    log_level = logging.DEBUG if args.verbose else logging.INFO

    if args.logfile:
        logging.basicConfig(level=log_level, format=log_fmt, filename=args.logfile, filemode='w')
    else:
        logging.basicConfig(level=log_level, format=log_fmt, stream=sys.stderr)

    # Also enable the speakeasy library logger at the right level
    for name in ["speakeasy", "speakeasy.windows", "speakeasy.binemu"]:
        logging.getLogger(name).setLevel(log_level)

    print(f"[*] Initializing Speakeasy emulator (debug={args.verbose})...")
    se = speakeasy.Speakeasy(debug=args.verbose)

    print(f"[*] Loading module: {args.file}...")
    module = se.load_module(path=args.file)
    if module is None:
        print("Error: Failed to load module", file=sys.stderr)
        sys.exit(1)
    print(f"    Base: 0x{module.base:x}  Entry: 0x{module.ep:x}  Size: 0x{module.image_size:x}")

    print(f"[*] Running module entry point...")
    se.run_module(module)
    print(f"[*] Emulation finished!")

    # Print report summary
    report = se.get_json_report()
    if args.report:
        with open(args.report, "w") as f:
            f.write(report)
        print(f"[*] Report saved to: {args.report}")
    else:
        try:
            import json
            r = json.loads(report)
            print(f"\n--- Report Summary ---")
            print(f"  Entry points: {len(r.get('entry_points', []))}")
            print(f"  API calls:    {len(r.get('api_events', r.get('api', [])))}")
            err_info = r.get('error_info')
            if err_info:
                print(f"  Error:        {err_info}")
            print(f"  Done.")
        except Exception:
            print(report[:2000] if len(report) > 2000 else report)


if __name__ == "__main__":
    main()
