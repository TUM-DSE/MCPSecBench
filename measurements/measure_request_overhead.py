
import re
import statistics
import sys

def parse_request_file(filename):
    """Parse the policy file and extract times for passed and failed policies."""
    times = []
    
    with open(filename, 'r') as f:
        for line in f:
            times.append(float(line.split(':')[1][:-2].strip()))
    
    return times

def calculate_stats(times, label):
    """Calculate and print statistics for a list of times."""
    if not times:
        print(f"\n{label}:")
        print("  No data available")
        return
    
    avg = statistics.mean(times)
    std = statistics.stdev(times) if len(times) > 1 else 0.0
    med = statistics.median(times)
    
    print(f"\n{label}:")
    print(f"  Count: {len(times)}")
    print(f"  Average: {avg:.6f} s")
    print(f"  Std Dev: {std:.6f} s")
    print(f'  Median: {med: 6f} s')

def main(filename : str):
    
    # Parse the file
    times = parse_request_file(filename)
    
    # Print statistics
    print("=" * 50)
    print("REQUEST EXECUTION STATISTICS")
    print("=" * 50)
    
    calculate_stats(times, "Overall")
    
    print("\n" + "=" * 50)

if __name__ == "__main__":
    if len(sys.argv) - 1 != 1:
        print(f"Usage: python {sys.argv[0]} <request_data_file_path>")
        exit(0)
    main(sys.argv[1])
