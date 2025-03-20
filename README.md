<h1>Shell Script to detect Compromised GitHub Action tj-actions/changed-files </h1>
A recent security breach has compromised the popular GitHub Action tj-actions/changed-files, potentially impacting thousands of CI pipelines. The affected action contains a payload that appears to be designed for stealing sensitive data, which can lead to significant security exposures in the targeted organizations. I intend to outline the risk and, provide a script to detect the affected repositories, suggests mitigation steps, and explains the process for assessing the potential impact on Amazon Web Services resources.
<br>On 14 March, 2025, it was revealed that GitHub Action tj-actions/changed-files had been compromised. The compromised action has embedded code that can steal secrets, thereby causing unauthorized disclosure of sensitive information to unauthorized people. This is not the first time a security flaw is linked to this action since it follows a newly discovered vulnerability (CVE-2023-51664). A deep dive using tag pointer analysis in the original repository found that all tj-actions/changed-files versions were compromised.
The threat to security here is significant as GitHub Actions very often have access to sensitive organizational data that includes cloud service credentials, API keys, and authentication tokens. The organizations  therefore has to take immediate action to identify affected repositories and prevent leakage of their information.
<h2>References</h2>
https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/
https://nvd.nist.gov/vuln/detail/CVE-2023-51664
