#Design habits to lock in from the very first call:
# - Question wording is literal, not intent-based: "reads a file that stores credentials", never "is this dangerous"
# - criteria.true/false boundaries written with examples — this is your prompt engineering surface
# - Named keys (touches_credentials) — answers come back under the same keys, so build your logging around them

 curl -s -X POST https://api.typesafe.ai/v1/systemone \
  -H "Authorization: Bearer $TYPESAFE_API_KEY" \
  -H "Content-Type: application/json" \
  -d @- <<'EOF'
{
  "state": "Tool call: read_file(path=\"/etc/shadow\") requested by agent role=developer, cwd=/home/user/project",
  "model": "jev-latest",
  "questions": {
    "touches_credentials": {
      "type": "noul",
      "instructions": "Does this tool call read a file that stores account credentials or authentication tokens?",
      "criteria": {"true": "Path points to passwords, keys, tokens, or secrets files", "false": "Path is ordinary project or system content"}
    }
  }
}
EOF