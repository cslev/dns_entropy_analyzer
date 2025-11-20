# dns_entropy_analyzer

This repository provides tools for analyzing domain lists and calculating Shannon entropy to detect potentially malicious domain names. The primary goal is to identify Domain Generation Algorithm (DGA) generated domains and other suspicious domain names through entropy analysis.

## Shannon Entropy

Shannon Entropy is a measure of randomness or unpredictability in data, developed by Claude Shannon in information theory. In the context of domain name analysis, entropy quantifies how random the characters in a domain name appear to be.

The Shannon entropy formula is:

```
H(X) = -Σ P(xi) * log2(P(xi))
```

Where:
- H(X) is the entropy
- P(xi) is the probability of character xi occurring in the string
- The sum is over all unique characters in the string

For domain names:
- **Low entropy** indicates predictable, human-readable domains (e.g., "google.com", "facebook.com")
- **High entropy** suggests random-looking domains that may be generated algorithmically (e.g., "xj4k2m9p.com")

Higher entropy values (typically above 3.5-4.0 for domain names) can indicate:
- DGA-generated domains used by malware for Command & Control (C2)
- Randomly generated subdomain names
- Obfuscated or encoded domain names

## DGA Domain Names

Domain Generation Algorithm (DGA) is a technique used by malware to generate a large number of pseudo-random domain names that can be used as rendezvous points with their command and control (C&C) servers.

### How DGAs Work

Malware families use DGAs to generate thousands of domain names periodically. The attackers only need to register a few of these domains to maintain communication with infected hosts, while defenders must block all possible domains or detect the pattern.

### Characteristics of DGA Domains

1. **High randomness**: DGA domains typically have high Shannon entropy
2. **Algorithmic generation**: Created by algorithms rather than humans
3. **Short lifespan**: Often registered for brief periods
4. **Difficult to predict**: Without knowing the algorithm, it's hard to predict which domains will be generated
5. **Character distribution**: Often have unusual character frequency patterns

### Examples of DGA Patterns

- **Conficker**: Uses date-based seed to generate domains
- **Cryptolocker**: Generates domains based on current date
- **Zeus/Gameover Zeus**: Uses pseudo-random domain generation

### Detection Strategy

By analyzing Shannon entropy of domains, we can:
1. Identify domains with unusually high entropy
2. Flag potential DGA-generated domains for further investigation
3. Block suspicious domains before they can be used for malicious purposes
4. Detect patterns in domain naming that may indicate compromise

This tool helps network administrators and security researchers identify potentially malicious domains by sorting them by entropy, with the highest entropy domains appearing at the top of the results.

## Usage

### Requirements

- Python 3.x (no external dependencies required)
- A text file containing domain names (one per line), or domain names piped from stdin

### Input File Format

Create a text file with domain names, one per line. You can optionally specify a count for each domain:

```
example.com
google.com 5
facebook.com 3
xj4k2m9pqrst.com
# Comments are ignored
amazon.com
```

The file format supports:
- Simple domain names (count defaults to 1)
- Domain names with counts (space or tab separated)
- Comments (lines starting with #)
- Empty lines (ignored)

### Running the Analyzer

```bash
python3 dns_entropy_analyzer.py [options]
```

**Options:**
- `--file FILE`: Path to a file containing domain names
- `--domains DOMAIN [DOMAIN ...]`: List of domain names to analyze directly
- `--top-n N`: Show only the top N domains by entropy (default: show all)

If no input options are provided, the script reads from stdin (allowing piping).

**Examples:**

```bash
# Analyze domains from a file
python3 dns_entropy_analyzer.py --file domains.txt

# Show only the top 50 domains with highest entropy
python3 dns_entropy_analyzer.py --file domains.txt --top-n 50

# Analyze a list of domains provided as arguments
python3 dns_entropy_analyzer.py --domains example.com google.com suspicious.domain

# Pipe domains from another command
cat domains.txt | python3 dns_entropy_analyzer.py

# Pipe from a command and limit output
some_command | python3 dns_entropy_analyzer.py --top-n 10

# Analyze domains from stdin interactively (not recommended for production)
echo -e "example.com\ngoogle.com" | python3 dns_entropy_analyzer.py

# Analyze pihole logs for DNS replies
cat pihole.log|grep reply|awk '{print $6}' | python3 dns_entropy_analyzer.py
```

### Output Format

The script produces a sorted table showing:
- **Domain Name**: The domain being analyzed
- **Entropy**: Shannon entropy value (higher = more random)
- **Count**: Number of occurrences (from input file)

Results are sorted by entropy (highest first), then by count.

### Example Output

```
=========================================================
Domain Name            |    Entropy |    Count
=========================================================
abc123xyz789qwerty.org |     4.0588 |        3
7h2k9mxpqwzv3r.com     |     3.8074 |        3
xj4k2m9pqrst.com       |     3.5850 |        3
facebook.com           |     2.7500 |        3
google.com             |     1.9183 |        5
=========================================================

Statistics:
  Average entropy: 2.8158
  Maximum entropy: 4.0588
  Minimum entropy: 1.9183

Domains with high entropy (>4.0) may indicate DGA-generated domains.
```

### Interpreting Results

- **Entropy > 4.0**: High probability of DGA-generated or suspicious domains
- **Entropy 3.5-4.0**: Moderately suspicious, worth investigating
- **Entropy < 3.0**: Likely legitimate, human-readable domains

Review high-entropy domains for potential security threats and consider blocking or further investigating them.

## License

See LICENSE file for details.
