#!/usr/bin/env python3
import sys
import json
from collections import defaultdict, Counter

def main():
    # Dictionary to track responses for each unique request
    request_responses = defaultdict(set)

    try:
        # Read JSON logs from standard input
        for line in sys.stdin:
            try:
                log_entry = json.loads(line.strip())

                # Extract relevant fields to identify unique requests
                request_key = (
                    log_entry.get('request.method', ''),
                    log_entry.get('request.requestURI', '')
                )

                # Extract the response body
                response_body = log_entry.get('response.body', '')

                # Skip entries with empty or null responses
                if not response_body:
                    continue

                # Add the response to the set for this request
                request_responses[request_key].add(response_body)
            except json.JSONDecodeError:
                # Skip lines that are not valid JSON
                continue

        # Aggregate and sort the top 10 most common requests
        top_10_requests = sorted(
            request_responses.items(),
            key=lambda x: len(x[1]),  # Sort by the number of unique responses
            reverse=True
        )[:10]

        # Print the top 10 requests with their responses, adding separators
        print("Top 10 Requests with Responses:")
        print("=" * 80)
        for idx, ((method, uri), responses) in enumerate(top_10_requests, start=1):
            print(f"{idx}. Method: {method}, URI: {uri}")
            for response in responses:
                print(f"   Response: '{response}'")
            if idx < len(top_10_requests):  # Add separator after each item except the last
                print("=" * 80)  # Example separator, you can adjust as needed

    except KeyboardInterrupt:
        # Gracefully handle Ctrl+C interruption
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

