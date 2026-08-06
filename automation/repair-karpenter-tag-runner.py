from pathlib import Path

path = Path("automation/apply-karpenter-tag-contract-fix.py")
text = path.read_text(encoding="utf-8")
replacements = {
    "if ($null -ne $Discovery) {": "if (-not [string]::IsNullOrWhiteSpace($Discovery)) {",
    "if ($null -ne $ClusterOwnership) {": "if (-not [string]::IsNullOrWhiteSpace($ClusterOwnership)) {",
    "if ($null -ne $OtherClusterOwnership) {": "if (-not [string]::IsNullOrWhiteSpace($OtherClusterOwnership)) {",
    "if ($null -ne $NodeClaim) {": "if (-not [string]::IsNullOrWhiteSpace($NodeClaim)) {",
    "if ($null -ne $NodePool) {": "if (-not [string]::IsNullOrWhiteSpace($NodePool)) {",
}
for old, new in replacements.items():
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected one fixture marker for {old!r}, received {count}")
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8", newline="\n")
