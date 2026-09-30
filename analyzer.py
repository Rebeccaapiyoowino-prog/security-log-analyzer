import argparse
import re
from collections import Counter
from pathlib import Path


FAILED_LOGIN = re.compile(
    r"Failed password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESSFUL_LOGIN = re.compile(
    r"Accepted password .* from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze_log(file_path: str, threshold: int = 5):
    failed_ips = Counter()
    successful_ips = Counter()

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {file_path}")

    with path.open("r", encoding="utf-8", errors="ignore") as log_file:
        for line in log_file:
            failed = FAILED_LOGIN.search(line)
            successful = SUCCESSFUL_LOGIN.search(line)

            if failed:
                failed_ips[failed.group("ip")] += 1

            if successful:
                successful_ips[successful.group("ip")] += 1

    suspicious = {
        ip: attempts
        for ip, attempts in failed_ips.items()
        if attempts >= threshold
    }

    return {
        "failed_logins": failed_ips,
        "successful_logins": successful_ips,
        "suspicious_ips": suspicious,
    }


def print_report(results):
    print("\n=== Security Log Analysis Report ===")

    print("\nFailed login attempts:")
    if results["failed_logins"]:
        for ip, count in results["failed_logins"].most_common():
            print(f"{ip}: {count}")
    else:
        print("None detected")

    print("\nSuccessful logins:")
    if results["successful_logins"]:
        for ip, count in results["successful_logins"].most_common():
            print(f"{ip}: {count}")
    else:
        print("None detected")

    print("\nPotential brute-force sources:")
    if results["suspicious_ips"]:
        for ip, count in results["suspicious_ips"].items():
            print(f"WARNING: {ip} generated {count} failed login attempts")
    else:
        print("No suspicious sources exceeded the threshold")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze Linux authentication logs for suspicious login activity."
    )

    parser.add_argument("logfile", help="Path to the authentication log")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed-login threshold for flagging an IP address",
    )

    args = parser.parse_args()

    results = analyze_log(args.logfile, args.threshold)
    print_report(results)


if __name__ == "__main__":
    main()
