import re
import statistics
import sys

def parse_policy_file(filename):
    """Parse the policy file and extract times for passed and failed policies."""
    passed_times = []
    failed_times = []
    
    with open(filename, 'r') as f:
        for line in f:
            # Extract status (Passed/Failed) and time
            match = re.search(r'\[Policy\] - (Passed|Failed): ([\d.]+) s', line)
            if match:
                status = match.group(1)
                time = float(match.group(2))
                
                if status == "Passed":
                    passed_times.append(time)
                elif status == "Failed":
                    failed_times.append(time)
    
    return passed_times, failed_times

def calculate_stats(times, label):
    """Calculate and print statistics for a list of times."""
    if not times:
        print(f"\n{label}:")
        print("  No data available")
        return
    
    avg = statistics.mean(times)
    std = statistics.stdev(times) if len(times) > 1 else 0.0
    
    print(f"\n{label}:")
    print(f"  Count: {len(times)}")
    print(f"  Average: {avg:.6f} s")
    print(f"  Std Dev: {std:.6f} s")

def main(filename : str):
    
    # Parse the file
    passed_times, failed_times = parse_policy_file(filename)
    all_times = passed_times + failed_times
    
    # Print statistics
    print("=" * 50)
    print("POLICY EXECUTION STATISTICS")
    print("=" * 50)
    
    calculate_stats(passed_times, "PASSED Policies")
    calculate_stats(failed_times, "FAILED Policies")
    calculate_stats(all_times, "OVERALL (All Policies)")
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    if len(sys.argv) - 1 != 1:
        print(f"Usage: python {sys.argv[0]} <policy_data_file_path>")
        exit(0)
    main(sys.argv[1])
