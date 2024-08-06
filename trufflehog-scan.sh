#!/bin/bash

# Variables
GITHUB_ORG="trufflesecurity"  # Replace with another GitHub organisation name as required. 
OUTPUT_DIR="./trufflehog_results"    # Directory to store output files
TRUFFLEHOG_OUTPUT="$OUTPUT_DIR/trufflehog_output.json"
CSV_OUTPUT="$OUTPUT_DIR/results_table.csv"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Run Trufflehog scan
echo "Running Trufflehog scan on public repositories of $GITHUB_ORG..."
trufflehog github --org="$GITHUB_ORG" --only-verified --json > "$TRUFFLEHOG_OUTPUT"

# Check if Trufflehog scan was successful
if [ $? -ne 0 ]; then
    echo "Trufflehog scan failed. Exiting."
    exit 1
fi

echo "Trufflehog scan completed. Processing results..."

# Initialize CSV file with headers
echo "Type,DetectorName,Raw,Repository,FilePath" > "$CSV_OUTPUT"

# Initialize counters
total_secrets=0
private_keys=0
tokens=0
credentials=0

# Process the Trufflehog output
while IFS= read -r line; do
    # Increment total secrets count
    ((total_secrets++))

    # Extract values
    detector_name=$(echo "$line" | jq -r '.DetectorName')
    raw_value=$(echo "$line" | jq -r '.Raw')
    repository=$(echo "$line" | jq -r '.SourceMetadata.Data.Github.repository')
    file_path=$(echo "$line" | jq -r '.SourceMetadata.Data.Github.file')

    # Categorize and write to CSV
    if [ "$detector_name" = "PrivateKey" ]; then
        echo "PrivateKey,$detector_name,\"$raw_value\",$repository,$file_path" >> "$CSV_OUTPUT"
        ((private_keys++))
    elif [[ "$detector_name" =~ ^(SlackWebhook|TwitterConsumerkey|BrowserStack|Mockaroo)$ ]]; then
        echo "Token,$detector_name,\"$raw_value\",$repository,$file_path" >> "$CSV_OUTPUT"
        ((tokens++))
    else
        echo "Credential,$detector_name,\"$raw_value\",$repository,$file_path" >> "$CSV_OUTPUT"
        ((credentials++))
    fi
done < "$TRUFFLEHOG_OUTPUT"

# Add total counts to the CSV
echo "Total,PrivateKeys,$private_keys,," >> "$CSV_OUTPUT"
echo "Total,Tokens,$tokens,," >> "$CSV_OUTPUT"
echo "Total,Credentials,$credentials,," >> "$CSV_OUTPUT"
echo "Total,AllSecrets,$total_secrets,," >> "$CSV_OUTPUT"

echo "Analysis complete. Results saved to $CSV_OUTPUT"
