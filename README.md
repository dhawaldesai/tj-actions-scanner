<h1>Shell Script to detect Compromised GitHub Action tj-actions/changed-files </h1>
A recent security breach has compromised the popular GitHub Action tj-actions/changed-files, potentially impacting thousands of CI pipelines. The affected action contains a payload that appears to be designed for stealing sensitive data, which can lead to significant security exposures in the targeted organizations. I intend to outline the risk and, provide a script to detect the affected repositories, suggests mitigation steps, and explains the process for assessing the potential impact on Amazon Web Services resources.
<br>On 14 March, 2025, it was revealed that GitHub Action tj-actions/changed-files had been compromised. The compromised action has embedded code that can steal secrets, thereby causing unauthorized disclosure of sensitive information to unauthorized people. This is not the first time a security flaw is linked to this action since it follows a newly discovered vulnerability (CVE-2023-51664). A deep dive using tag pointer analysis in the original repository found that all tj-actions/changed-files versions were compromised.
The threat to security here is significant as GitHub Actions very often have access to sensitive organizational data that includes cloud service credentials, API keys, and authentication tokens. The organizations  therefore has to take immediate action to identify affected repositories and prevent leakage of their information.
<h2>Security Fixes (April 2026)</h2>
The following security issues were identified and fixed in <code>tj-action-verify.sh</code>:

<ul>
  <li><strong>Shell strict mode:</strong> Added <code>set -euo pipefail</code> to catch unset variables, command failures, and pipe errors early.</li>
  <li><strong>Input validation on organization name:</strong> The script now uses <code>read -r</code> and exits with an error if the GitHub organization name is left empty.</li>
  <li><strong>Word splitting on <code>find</code> output:</strong> Replaced the unsafe <code>for REPO_GIT in $REPOS</code> loop with <code>find -print0 | while IFS= read -r -d ''</code> to correctly handle directory paths containing spaces or special characters.</li>
  <li><strong>Null-delimited <code>xargs</code>:</strong> Updated <code>find | xargs grep</code> to use <code>find -print0 | xargs -0 grep</code> to safely handle filenames with spaces or newlines.</li>
  <li><strong>Fixed <code>find</code> expression grouping:</strong> Added <code>\( \)</code> around the <code>-name "*.yml" -o -name "*.yaml"</code> clause to ensure correct logical grouping with <code>-type f</code>.</li>
  <li><strong><code>read</code> without <code>-r</code>:</strong> All <code>read</code> calls now use the <code>-r</code> flag to prevent backslash interpretation from user input.</li>
  <li><strong>Broken pipe syntax:</strong> Removed the stray backslash before <code>jq</code> (<code>\jq</code>) in the GitHub CLI pipe.</li>
  <li><strong>Unquoted variable in URL:</strong> Fixed <code>"$ORG"</code> being outside the double-quoted string in the report output; now uses <code>${ORG}</code> consistently inside the string.</li>
</ul>

<h2>References</h2>
https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/
https://nvd.nist.gov/vuln/detail/CVE-2023-51664
