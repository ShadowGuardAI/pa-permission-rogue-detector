#!/usr/bin/env python3

import argparse
import logging
import os
import stat
import sys
from collections import defaultdict
from typing import List, Dict, Set, Tuple

try:
    import pathspec
    from rich.console import Console
    from rich.table import Column, Table
except ImportError as e:
    print(f"Error importing required libraries: {e}. Please install them (e.g., pip install pathspec rich)")
    sys.exit(1)


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """Sets up the argument parser for the command-line interface."""
    parser = argparse.ArgumentParser(
        description="Identifies rogue file system permissions based on statistical analysis and anomaly detection.",
        epilog="Example: pa-permission-rogue-detector -d /path/to/scan -b /path/to/baseline"
    )

    parser.add_argument(
        "-d",
        "--directory",
        type=str,
        required=True,
        help="The directory to scan for permissions anomalies."
    )

    parser.add_argument(
        "-b",
        "--baseline",
        type=str,
        required=False,
        help="Path to a file containing a baseline of acceptable permissions.  "
             "If not provided, a basic analysis will be performed based on the scan directory only."
    )

    parser.add_argument(
        "-e",
        "--exclude",
        type=str,
        nargs='+',
        help="File or directory patterns to exclude from the scan (e.g., '*.log' 'temp_dir/*').  Uses gitignore-style patterns.",
    )

    parser.add_argument(
        "-t",
        "--threshold",
        type=float,
        default=2.0,  # Default threshold value
        help="Threshold for anomaly detection. Higher values mean less sensitivity. Defaults to 2.0.",
    )

    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Path to output the rogue permissions report to a file (optional)."
    )

    parser.add_argument(
        "--check-suid-sgid",
        action="store_true",
        help="Check for SUID/SGID bits set on files (potential privilege escalation risk)."
    )

    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output."
    )
    
    return parser.parse_args()


def is_excluded(path: str, exclude_patterns: List[str] = None) -> bool:
    """Checks if a path is excluded based on provided patterns."""
    if not exclude_patterns:
        return False

    try:
        spec = pathspec.PathSpec.from_lines('gitwildmatch', exclude_patterns)
        return spec.match_file(path)
    except Exception as e:
        logging.error(f"Error processing exclude patterns: {e}")
        return False  # Default to not excluded to avoid unintended skips

def get_file_permissions(filepath: str) -> str:
    """Gets the file permissions in a human-readable format (e.g., 'rwxr-xr--')."""
    try:
        st = os.stat(filepath)
        mode = st.st_mode
        perms = ""
        perms += "r" if mode & stat.S_IRUSR else "-"
        perms += "w" if mode & stat.S_IWUSR else "-"
        perms += "x" if mode & stat.S_IXUSR else "-"
        perms += "r" if mode & stat.S_IRGRP else "-"
        perms += "w" if mode & stat.S_IWGRP else "-"
        perms += "x" if mode & stat.S_IXGRP else "-"
        perms += "r" if mode & stat.S_IROTH else "-"
        perms += "w" if mode & stat.S_IWOTH else "-"
        perms += "x" if mode & stat.S_IXOTH else "-"
        return perms
    except OSError as e:
        logging.error(f"Error getting permissions for {filepath}: {e}")
        return "---------"

def analyze_permissions(directory: str, exclude_patterns: List[str] = None) -> Dict[str, int]:
    """Analyzes permissions in a directory, counting occurrences of each permission string."""
    permission_counts = defaultdict(int)
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                if is_excluded(filepath, exclude_patterns):
                    logging.debug(f"Skipping excluded file: {filepath}")
                    continue
                perms = get_file_permissions(filepath)
                permission_counts[perms] += 1
    except OSError as e:
        logging.error(f"Error walking directory {directory}: {e}")
    return permission_counts


def load_baseline_permissions(baseline_file: str) -> Dict[str, int]:
    """Loads baseline permissions from a file."""
    baseline = defaultdict(int)
    try:
        with open(baseline_file, "r") as f:
            for line in f:
                perm, count = line.strip().split(",")
                baseline[perm] = int(count)
    except FileNotFoundError:
        logging.error(f"Baseline file not found: {baseline_file}")
        return {}
    except ValueError:
        logging.error(f"Invalid format in baseline file: {baseline_file}. Expected 'permission,count'.")
        return {}
    except Exception as e:
        logging.error(f"Error loading baseline from {baseline_file}: {e}")
        return {}

    return baseline


def detect_anomalies(
    scan_permissions: Dict[str, int],
    baseline_permissions: Dict[str, int],
    threshold: float,
) -> Dict[str, Tuple[int, float]]:
    """Detects permission anomalies based on a statistical comparison with a baseline."""
    anomalies: Dict[str, Tuple[int, float]] = {}  # Store permission, count, and Z-score
    total_baseline_count = sum(baseline_permissions.values())
    if total_baseline_count == 0:
        logging.warning("Baseline contains no data.  No anomalies can be reliably detected.")
        return {}

    for perm, scan_count in scan_permissions.items():
        baseline_prob = baseline_permissions.get(perm, 0) / total_baseline_count if total_baseline_count > 0 else 0
        expected_scan_count = baseline_prob * sum(scan_permissions.values())

        # Calculate Z-score
        if expected_scan_count > 0:
            z_score = (scan_count - expected_scan_count) / (expected_scan_count**0.5)
        else:
            z_score = float('inf') if scan_count > 0 else 0.0 # Flag as anomalous if found in scan but not baseline.

        if abs(z_score) > threshold:
            anomalies[perm] = (scan_count, z_score)

    return anomalies


def check_suid_sgid(directory: str, exclude_patterns: List[str] = None) -> List[str]:
    """Checks for SUID/SGID bits set on files."""
    suid_sgid_files = []
    try:
        for root, _, files in os.walk(directory):
            for file in files:
                filepath = os.path.join(root, file)
                if is_excluded(filepath, exclude_patterns):
                    continue
                try:
                    st = os.stat(filepath)
                    if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                        suid_sgid_files.append(filepath)
                except OSError as e:
                    logging.error(f"Error checking SUID/SGID bits for {filepath}: {e}")
    except OSError as e:
        logging.error(f"Error walking directory {directory}: {e}")
    return suid_sgid_files


def output_results(
    anomalies: Dict[str, Tuple[int, float]],
    suid_sgid_files: List[str],
    output_file: str = None,
    no_color: bool = False,
):
    """Outputs the results to the console and optionally to a file."""
    console = Console(no_color=no_color)

    # Anomalies Table
    if anomalies:
        table = Table(title="Permission Anomalies", show_header=True, header_style="bold magenta")
        table.add_column("Permission", style="cyan")
        table.add_column("Count", style="magenta")
        table.add_column("Z-Score", style="green")

        for perm, (count, z_score) in anomalies.items():
            table.add_row(perm, str(count), f"{z_score:.2f}")

        console.print(table)

        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write("Permission Anomalies:\n")
                    for perm, (count, z_score) in anomalies.items():
                        f.write(f"Permission: {perm}, Count: {count}, Z-Score: {z_score:.2f}\n")
            except IOError as e:
                logging.error(f"Error writing to output file: {e}")


    # SUID/SGID Files List
    if suid_sgid_files:
        console.print("\n[bold red]SUID/SGID Files (Potential Privilege Escalation Risk):[/]")
        for filepath in suid_sgid_files:
            console.print(f"[red]{filepath}[/]")

        if output_file:
            try:
                with open(output_file, "a") as f:
                    f.write("\nSUID/SGID Files (Potential Privilege Escalation Risk):\n")
                    for filepath in suid_sgid_files:
                        f.write(f"{filepath}\n")
            except IOError as e:
                logging.error(f"Error writing to output file: {e}")
    elif not anomalies:
        console.print("[green]No anomalies or SUID/SGID files found.[/]")
        if output_file:
            try:
                with open(output_file, "w") as f:
                    f.write("No anomalies or SUID/SGID files found.\n")
            except IOError as e:
                logging.error(f"Error writing to output file: {e}")


def main():
    """Main function to execute the permission rogue detector."""
    args = setup_argparse()

    # Input validation
    if not os.path.isdir(args.directory):
        logging.error(f"Error: Directory '{args.directory}' does not exist.")
        sys.exit(1)

    if args.baseline and not os.path.isfile(args.baseline):
        logging.error(f"Error: Baseline file '{args.baseline}' does not exist.")
        sys.exit(1)
    
    if args.threshold <= 0:
        logging.error("Error: Threshold must be a positive number.")
        sys.exit(1)

    # Perform analysis
    scan_permissions = analyze_permissions(args.directory, args.exclude)

    if args.baseline:
        baseline_permissions = load_baseline_permissions(args.baseline)
        if not baseline_permissions:
            logging.error("No baseline data loaded. Exiting.")
            sys.exit(1)

        anomalies = detect_anomalies(scan_permissions, baseline_permissions, args.threshold)
    else:
        logging.info("No baseline provided. Skipping anomaly detection.")
        anomalies = {}  # No anomalies if no baseline

    suid_sgid_files = []
    if args.check_suid_sgid:
        suid_sgid_files = check_suid_sgid(args.directory, args.exclude)

    # Output results
    output_results(anomalies, suid_sgid_files, args.output, args.no_color)


if __name__ == "__main__":
    main()