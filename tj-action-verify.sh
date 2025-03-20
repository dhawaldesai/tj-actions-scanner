#!/bin/bash

# Script to detect compromised tj-actions/changed-files in GitHub repositories
# Date: March 17, 2025

echo "=========================================================="
echo "  DETECTION SCRIPT FOR TJ-ACTIONS/CHANGED-FILES COMPROMISE"
echo "=========================================================="
echo ""

# Create output directory
OUTPUT_DIR="tj_actions_scan_results_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
REPORT_FILE="$OUTPUT_DIR/scan_report.txt"
AFFECTED_REPOS="$OUTPUT_DIR/affected_repositories.txt"
WORKFLOW_FILES="$OUTPUT_DIR/affected_workflow_files.txt"
touch "$REPORT_FILE"
touch "$AFFECTED_REPOS"
touch "$WORKFLOW_FILES"


echo "Scan initiated on $(date)" > "$REPORT_FILE"
echo "Results will be saved to $OUTPUT_DIR"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Detect GitHub organization
    read -p "Please enter your GitHub organization name: " ORG

echo "Organization: $ORG" >> "$REPORT_FILE"
echo ""

# Method 1: GitHub Search (if GitHub CLI is available)
echo "Method 1: Using GitHub Search API"
if command_exists gh; then
    echo "Using GitHub CLI to search for affected repositories..."
    echo "Searching for 'uses: tj-actions' in $ORG organization..."
    
    #gh search code --owner "$ORG" tj-actions
    gh search code 'tj-actions/changed-files' --owner "$ORG" --json repository,path,url | \jq -r '.[] | "Repository: " + .repository.nameWithOwner + ", File: " + .path + ", URL: " + .url' | tee -a "$WORKFLOW_FILES"
    #gh search code --owner hivemq tj-actions/changed-files@v42 --json repository,path,url | \ jq -r '.[] | "Repository: " + .repository.nameWithOwner + ", File: " + .path + ", URL: " + .url' | \tee -a "$WORKFLOW_FILES"
    echo "GitHub search results saved to $WORKFLOW_FILES"
    
    # Extract unique repository names
    cat "$WORKFLOW_FILES" | grep "Repository:" | cut -d":" -f2- | sed 's/^[ \t]*//' | sort | uniq > "$AFFECTED_REPOS"
    REPO_COUNT=$(wc -l < "$AFFECTED_REPOS")
    echo "Found $REPO_COUNT potentially affected repositories."
    echo "$REPO_COUNT repositories potentially affected via GitHub search" >> "$REPORT_FILE"
else
    echo "GitHub CLI not installed. Skipping GitHub search method."
    echo "To use this method, install GitHub CLI and authenticate with: gh auth login"
    echo "Method 1 skipped: GitHub CLI not installed" >> "$REPORT_FILE"
fi
echo ""

# Method 2: Local Repository Scan
echo "Method 2: Local Repository Scan"
echo "Enter the path to your local repositories (or press Enter to skip):"
read LOCAL_PATH

if [ -n "$LOCAL_PATH" ] && [ -d "$LOCAL_PATH" ]; then
    echo "Scanning local repositories at $LOCAL_PATH..."
    echo "Local scan path: $LOCAL_PATH" >> "$REPORT_FILE"
    
    # Find all .git directories
    REPOS=$(find "$LOCAL_PATH" -name ".git" -type d -prune)
    LOCAL_AFFECTED="$OUTPUT_DIR/local_affected_repos.txt"
    
    for REPO_GIT in $REPOS; do
        REPO_DIR=$(dirname "$REPO_GIT")
        REPO_NAME=$(basename "$REPO_DIR")
        echo "Scanning $REPO_NAME..."
        
        # Look for tj-actions in workflow files
        if grep -r "tj-actions/changed-files" "$REPO_DIR/.github" 2>/dev/null; then
            echo "$REPO_NAME: AFFECTED" | tee -a "$LOCAL_AFFECTED"
            find "$REPO_DIR/.github" -type f -name "*.yml" -o -name "*.yaml" | xargs grep -l "tj-actions/changed-files" 2>/dev/null >> "$OUTPUT_DIR/${REPO_NAME}_affected_files.txt"
        else
            echo "$REPO_NAME: CLEAR"
        fi
    done
    
    if [ -f "$LOCAL_AFFECTED" ]; then
        LOCAL_COUNT=$(wc -l < "$LOCAL_AFFECTED")
        echo "Found $LOCAL_COUNT affected repositories in local scan."
        echo "$LOCAL_COUNT repositories affected via local scan" >> "$REPORT_FILE"
    else
        echo "No affected repositories found in local scan."
        echo "0 repositories affected via local scan" >> "$REPORT_FILE"
    fi
else
    echo "Skipping local repository scan."
    echo "Method 2 skipped: No local path provided or invalid path" >> "$REPORT_FILE"
fi
echo ""

# Method 3: Semgrep Scan (if available)
echo "Method 3: Semgrep Scan"
if command_exists semgrep; then
    echo "Semgrep detected. Would you like to run a Semgrep scan? (y/n)"
    read RUN_SEMGREP
    
    if [[ "$RUN_SEMGREP" == "y" || "$RUN_SEMGREP" == "Y" ]]; then
        echo "Enter the path to scan with Semgrep:"
        read SEMGREP_PATH
        
        if [ -d "$SEMGREP_PATH" ]; then
            echo "Running Semgrep scan on $SEMGREP_PATH..."
            echo "Semgrep scan path: $SEMGREP_PATH" >> "$REPORT_FILE"
            
            # Run the specialized rule if possible
            if semgrep --config r/10Uz5qo/semgrep.tj-actions-compromised --json "$SEMGREP_PATH" > "$OUTPUT_DIR/semgrep_results.json" 2>/dev/null; then
                echo "Semgrep specialized scan completed successfully."
            else
                # Fallback to generic pattern matching
                echo "Could not use specialized rule. Falling back to generic pattern..."
                semgrep -e "uses: tj-actions/changed-files" -l yaml --json "$SEMGREP_PATH" > "$OUTPUT_DIR/semgrep_results.json"
            fi
            
            # Process semgrep results
            SEMGREP_MATCHES=$(jq '.results | length' "$OUTPUT_DIR/semgrep_results.json")
            echo "Semgrep found $SEMGREP_MATCHES matching patterns."
            echo "$SEMGREP_MATCHES matches found by Semgrep" >> "$REPORT_FILE"
            
            # Extract affected files
            jq -r '.results[] | .path' "$OUTPUT_DIR/semgrep_results.json" > "$OUTPUT_DIR/semgrep_affected_files.txt"
        else
            echo "Invalid path for Semgrep scan."
            echo "Method 3 aborted: Invalid Semgrep scan path" >> "$REPORT_FILE"
        fi
    else
        echo "Skipping Semgrep scan."
        echo "Method 3 skipped: User opted out" >> "$REPORT_FILE"
    fi
else
    echo "Semgrep not installed. Skipping Semgrep scan."
    echo "To use this method, install Semgrep: pip install semgrep"
    echo "Method 3 skipped: Semgrep not installed" >> "$REPORT_FILE"
fi
echo ""
echo "Generating comprehensive report..."
echo "" >> "$REPORT_FILE"
echo "=========================================================" >> "$REPORT_FILE"
echo "RECOMMENDATIONS AND NEXT STEPS:" >> "$REPORT_FILE"
echo "=========================================================" >> "$REPORT_FILE"
echo "1. Immediately remove tj-actions/changed-files from ALL branches" >> "$REPORT_FILE"
echo "2. Configure GitHub to prevent this action from running: https://github.com/organizations/"$ORG"/settings/actions" >> "$REPORT_FILE"
echo "3. Audit workflow run logs for signs of compromise" >> "$REPORT_FILE"
echo "4. Rotate ALL secrets that could have been exposed" >> "$REPORT_FILE"
echo "5. Check AWS CloudTrail and CloudWatch for suspicious activity" >> "$REPORT_FILE"
echo "6. Pin all GitHub Actions to specific commit SHAs instead of version tags" >> "$REPORT_FILE"

echo ""
echo "=========================================================="
echo "SCAN COMPLETE - Results saved to $OUTPUT_DIR"
echo "=========================================================="
echo "Review the report file for details: $REPORT_FILE"
echo ""
echo "IMMEDIATE ACTIONS REQUIRED:"
echo "1. Remove tj-actions/changed-files from all branches"
echo "2. Consider ALL secrets potentially compromised"
echo "3. Rotate affected credentials immediately"
echo "4. Review the AWS impact assessment section in the report"
echo "=========================================================="

