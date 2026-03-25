#!/usr/bin/env bash
# Simulates the Claude Code plugin install experience
# Run: asciinema rec assets/demo.cast -c 'bash assets/record.sh'

simulate_typing() {
    local text="$1"
    for (( i=0; i<${#text}; i++ )); do
        printf '%s' "${text:$i:1}"
        sleep 0.04
    done
}

clear

printf '\033[1;34m❯\033[0m '
simulate_typing "/plugin marketplace add makash/agent-infra-security"
sleep 0.3
echo ""
sleep 0.5
echo "  Added makash/agent-infra-security to plugin marketplace"
sleep 1.5

echo ""
printf '\033[1;34m❯\033[0m '
simulate_typing "/plugin install supply-chain-skills@agent-infra-security"
sleep 0.3
echo ""
sleep 0.5
echo "  ✓ Installed: pypi-supply-chain-response"
echo "  ✓ Installed: supply-chain-security-check"
sleep 2

echo ""
printf '\033[1;34m❯\033[0m '
simulate_typing "litellm got backdoored. Am I affected?"
sleep 0.3
echo ""
sleep 1

echo ""
echo "  Activating skill: pypi-supply-chain-response"
echo ""
echo "  Phase 1: Exposure Check"
echo "  Running: pip show litellm | grep Version"
echo "  Running: pipdeptree -r -p litellm"
echo ""
echo "  litellm==1.82.7"
echo "    └── dspy-ai==2.5.41 [requires: litellm>=1.64.0]"
echo "    └── crewai==0.28.0 [requires: litellm>=1.44.0]"
echo ""
printf '  \033[1;31m⚠ COMPROMISED VERSION INSTALLED\033[0m\n'
echo "  You never installed litellm — dspy and crewai pulled it in."
echo ""
echo "  Proceeding to Phase 2: Version Confirmation..."
sleep 4
