"""
sptest.py  Speakeasy Python test runner for log comparison with C++ port.

Usage:
  python sptest.py -v d:/path/to/sample.exe          # verbose to stderr
  python sptest.py -v -l py.log d:/path/to/sample.exe  # verbose to file
  python sptest.py d:/path/to/sample.exe              # generates sptest_<basename>.json

Compare with C++ logs:
  .\\build\\Debug\\speakeasy-cli.exe -v -t d:\\path\\to\\sample.exe 2> cpp.log
"""

import sys
import os
import json
import logging
import argparse
import datetime
import speakeasy


def main():
    parser = argparse.ArgumentParser(description="Emulate a PE using Speakeasy (Python)")
    parser.add_argument("file", help="Path of PE file to emulate")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose (DEBUG) logging")
    parser.add_argument("-l", "--logfile", type=str, default=None, help="Write log to file instead of stderr")
    parser.add_argument("-r", "--report", type=str, default=None, help="Write JSON report to path (default: auto)")
    parser.add_argument("--no-report", action="store_true", help="Skip JSON report generation")
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

    t_start = datetime.datetime.now()

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

    t_end = datetime.datetime.now()
    elapsed = (t_end - t_start).total_seconds()
    print(f"[*] Emulation finished! ({elapsed:.2f}s)")

    # Build structured JSON report
    if not args.no_report:
        raw_json = se.get_json_report()
        try:
            report_data = json.loads(raw_json)
        except Exception:
            report_data = {"raw": raw_json[:10000] if len(raw_json) > 10000 else raw_json}

        # Add metadata
        report_data["_metadata"] = {
            "tool": "sptest.py",
            "file": os.path.abspath(args.file),
            "filename": os.path.basename(args.file),
            "emulated": True,
            "elapsed_seconds": elapsed,
            "timestamp": t_end.isoformat(),
        }

        # Add entry summary
        entry_pts = report_data.get("entry_points", [])
        api_events = report_data.get("api_events", report_data.get("api", []))
        report_data["_summary"] = {
            "entry_points": len(entry_pts),
            "api_calls": len(api_events),
            "error_info": report_data.get("error_info"),
        }

        # Determine report path
        if args.report:
            report_path = args.report
        else:
            base = os.path.splitext(os.path.basename(args.file))[0]
            report_path = f"sptest_{base}.json"

        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        print(f"[*] JSON report saved to: {report_path}")

        # Print summary to stdout
        summary = report_data["_summary"]
        print(f"\n--- Report Summary ---")
        print(f"  Entry points: {summary['entry_points']}")
        print(f"  API calls:    {summary['api_calls']}")
        err = summary.get("error_info")
        if err:
            print(f"  Error:        {err}")
        print(f"  Report:       {report_path}")
    else:
        print(f"[*] (--no-report, skipping JSON output)")


if __name__ == "__main__":
    main()
