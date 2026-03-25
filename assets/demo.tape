# agent-infra-security demo
# Run: vhs assets/demo.tape

Output assets/demo.gif

Set FontSize 22
Set Width 1200
Set Height 600
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 40ms

# Scene 1: Install the plugin
Type "# Install the security skills"
Enter
Sleep 500ms

Type '/plugin marketplace add makash/agent-infra-security'
Enter
Sleep 2s

Type '/plugin install supply-chain-skills@agent-infra-security'
Enter
Sleep 2s

# Scene 2: Use it
Type ""
Enter
Sleep 500ms
Type "# Now just ask about any incident"
Enter
Sleep 500ms

Type 'litellm got backdoored — versions 1.82.7 and 1.82.8. Am I affected?'
Enter
Sleep 3s

# Scene 3: Show it working
Type ""
Enter
Sleep 300ms
Type "# The skill checks transitive deps, hunts for IOCs,"
Enter
Type "# rotates credentials, and generates a full runbook."
Enter
Sleep 2s

# Scene 4: Manual fallback
Type ""
Enter
Sleep 300ms
Type "# Or skip the agent — just run the script:"
Enter
Sleep 500ms

Type './scripts/check_compromise_template.sh litellm --dry-run'
Enter
Sleep 3s

Sleep 2s
