# AgentGate Demo

Shows an AI agent compromised by prompt injection — its output looks
clean while AgentGate silently blocks credential theft, path traversal,
and data exfiltration at the tool call layer.

## Run it

```bash
pip install agentgate-py
python examples/demo_agent/run_demo.py
```

No API keys or external services required.

## What you're seeing

Left panel: what the agent says it is doing  
Right panel: what it is actually attempting

The agent completes its task and reports success.  
AgentGate blocked 3 attacks the agent never mentioned.
