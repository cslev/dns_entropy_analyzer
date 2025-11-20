#!/usr/bin/env python3
"""
DNS Entropy Analyzer

This script analyzes domain lists and calculates Shannon entropy
for domain names to identify potentially malicious DGA-generated domains.
"""

import sys
import re
import math
import argparse
from collections import Counter, defaultdict
from typing import Dict, List, Tuple


def calculate_shannon_entropy(domain: str) -> float:
  """
  Calculate Shannon entropy for a given domain name.

  Shannon entropy formula: H(X) = -Σ P(xi) * log2(P(xi))

  Args:
      domain: The domain name string to analyze

  Returns:
      float: The Shannon entropy value
  """
  if not domain:
    return 0.0
  # Remove the TLD for more accurate entropy calculation of the actual domain
  # We focus on the subdomain and domain parts, not the extension
  domain_without_tld = domain.rsplit('.', 1)[0] if '.' in domain else domain
  # print("Calculating entropy for domain:", domain_without_tld)
  # Count character frequencies
  char_counts = Counter(domain_without_tld.lower())
  length = len(domain_without_tld)
  # Calculate entropy
  entropy = 0.0
  for count in char_counts.values():
    probability = count / length
    entropy -= probability * math.log2(probability)
  return entropy


def read_domain_list(file_obj) -> Dict[str, int]:
  """
  Read a list of domain names from a file object (file or stdin).

  File format should have one domain per line. Lines can contain:
  - Just the domain name: "example.com"
  - Domain with count (space or tab separated): "example.com 5"
  - Comments starting with # are ignored
  - Empty lines are ignored

  Args:
      file_obj: An open file object (e.g., from open() or sys.stdin)

  Returns:
      Dictionary mapping domain names to their count (1 if not specified)
  """
  domain_counts = defaultdict(int)
  try:
    for line_num, line in enumerate(file_obj, 1):
      # Strip whitespace
      line = line.strip()
      # Skip empty lines and comments
      if not line or line.startswith('#'):
        continue
      # Parse line: domain [count]
      parts = line.split()
      if not parts:
        continue
      domain = parts[0]
      count = 1
      # If count is provided, parse it
      if len(parts) >= 2:
        try:
          count = int(parts[1])
          if count < 1:
            print(f"Warning: Invalid count on line {line_num}, using 1", file=sys.stderr)
            count = 1
        except ValueError:
          # If second field is not a number, just use count=1
          pass
      # Clean and validate domain
      domain = domain.rstrip('.')
      # Basic validation: must contain at least one dot and alphanumeric chars
      if '.' in domain and re.match(r'^[a-zA-Z0-9.-]+$', domain):
        domain_counts[domain] += count
      else:
        print(f"Warning: Invalid domain format on line {line_num}: {domain}", file=sys.stderr)
  except Exception as e:
    print(f"Error reading input: {e}", file=sys.stderr)
    sys.exit(1)
  return dict(domain_counts)


def analyze_domains(domains: Dict[str, int]) -> List[Tuple[str, float, int]]:
  """
  Calculate entropy for each domain and prepare sorted results.

  Args:
      domains: Dictionary mapping domain names to query counts

  Returns:
      List of tuples (domain, entropy, count) sorted by entropy (highest first)
  """
  results = []
  for domain, count in domains.items():
    entropy = calculate_shannon_entropy(domain)
    results.append((domain, entropy, count))
  # Sort by entropy (descending), then by count (descending)
  results.sort(key=lambda x: (-x[1], -x[2]))
  return results


def print_results(results: List[Tuple[str, float, int]], top_n: int = None):
  """
  Print the analysis results in a formatted table.

  Args:
      results: List of tuples (domain, entropy, count)
      top_n: Optional limit to print only top N results
  """
  if not results:
      print("No domains found in the log file.")
      return
  # Determine how many results to show
  display_results = results[:top_n] if top_n else results
  # Calculate column widths
  max_domain_len = max(len(r[0]) for r in display_results)
  max_domain_len = max(max_domain_len, len("Domain Name"))
  # Print header
  print("\n" + "=" * (max_domain_len + 35))
  print(f"{'Domain Name':<{max_domain_len}} | {'Entropy':>10} | {'Count':>8}")
  print("=" * (max_domain_len + 35))
  # Print results
  for domain, entropy, count in display_results:
    print(f"{domain:<{max_domain_len}} | {entropy:>10.4f} | {count:>8}")
  print("=" * (max_domain_len + 35))
  print(f"\nTotal unique domains analyzed: {len(results)}")
  if top_n and len(results) > top_n:
    print(f"Showing top {top_n} domains by entropy")
  print()


def main():
  """
  Main entry point for the DNS entropy analyzer.
  """
  parser = argparse.ArgumentParser(
    description="Analyze domain lists and calculate Shannon entropy to identify potentially malicious DGA-generated domains.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog="""
File format:
  example.com
  google.com 5
  # Comments are ignored

Examples:
  python3 dns_entropy_analyzer.py --file domains.txt
  python3 dns_entropy_analyzer.py --file domains.txt --top-n 50
  python3 dns_entropy_analyzer.py --domains example.com bad.com
  cat domains.txt | python3 dns_entropy_analyzer.py
  some_command | python3 dns_entropy_analyzer.py --top-n 10
  cat pihole.log|grep reply|awk '{print $6}' | python3 dns_entropy_analyzer.py
    """
  )
  parser.add_argument('--file', help='Path to a file containing domain names (one per line)')
  parser.add_argument('--domains', nargs='+', help='List of domain names to analyze')
  parser.add_argument('--top-n', type=int, help='Show only top N domains by entropy (default: all)')
  
  args = parser.parse_args()
  
  # Determine input source
  if args.file:
    print(f"Analyzing domain list from file: {args.file}")
    try:
      file_obj = open(args.file, 'r', encoding='utf-8', errors='ignore')
    except FileNotFoundError:
      print(f"Error: File '{args.file}' not found.", file=sys.stderr)
      sys.exit(1)
    domains = read_domain_list(file_obj)
    file_obj.close()
  elif args.domains:
    print("Analyzing provided domain list")
    # Create a dict from the list
    domains = defaultdict(int)
    for domain in args.domains:
      domain = domain.rstrip('.')
      if '.' in domain and re.match(r'^[a-zA-Z0-9.-]+$', domain):
        domains[domain] += 1
      else:
        print(f"Warning: Invalid domain format: {domain}", file=sys.stderr)
    domains = dict(domains)
  else:
    # Read from stdin
    if sys.stdin.isatty():
      print("No input specified. Use --file, --domains, or pipe input.", file=sys.stderr)
      parser.print_help()
      sys.exit(1)
    print("Analyzing domain list from stdin")
    domains = read_domain_list(sys.stdin)
  
  if not domains:
    print("No valid domains found in the input.")
    sys.exit(0)
  
  print(f"Found {len(domains)} unique domain names")
  print("Calculating Shannon entropy for each domain...")
  
  # Analyze domains and calculate entropy
  results = analyze_domains(domains)
  
  # Print results
  print_results(results, args.top_n)
  
  # Print some statistics
  if results:
    entropies = [r[1] for r in results]
    avg_entropy = sum(entropies) / len(entropies)
    max_entropy = max(entropies)
    min_entropy = min(entropies)
    print("Statistics:")
    print(f"  Average entropy: {avg_entropy:.4f}")
    print(f"  Maximum entropy: {max_entropy:.4f}")
    print(f"  Minimum entropy: {min_entropy:.4f}")
    print(f"\nDomains with high entropy (>4.0) may indicate DGA-generated domains.")


if __name__ == "__main__":
  main()
