#!/usr/bin/python3

import sys
import json
from collections import defaultdict, Counter

def main():
    if len(sys.argv) != 3:
        print("Usage: cat beelzebub.json | ./top10b.py <top_inputs> <top_outputs>")
        sys.exit(1)
    
    try:
        top_inputs = int(sys.argv[1])
        top_outputs = int(sys.argv[2])
    except ValueError:
        print("Error: Both arguments must be integers.")
        sys.exit(1)
    
    input_output_map = defaultdict(Counter)
    
    for line in sys.stdin:
        try:
            log_entry = json.loads(line.strip())
            if 'input' in log_entry and 'output' in log_entry and log_entry['input'] and log_entry['output']:
                input_output_map[log_entry['input']][log_entry['output']] += 1
        except json.JSONDecodeError:
            continue
    
    print(f"Top {top_inputs} Inputs with Output:")
    print("=" * 80)
    for idx, (input_cmd, outputs) in enumerate(sorted(input_output_map.items(), key=lambda x: sum(x[1].values()), reverse=True)[:top_inputs], 1):
        print(f"{idx}. Input: {input_cmd}")
        for output, count in outputs.most_common(top_outputs):  # Limit to specified top outputs
            print(f"   Output ({count}): {output}")
        print("=" * 80)

if __name__ == "__main__":
    main()


