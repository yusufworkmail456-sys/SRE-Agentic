# Server Agent install (monitored VM)

```bash
# 1. install
pip install /path/to/agent/            # or: uv pip install git+.../SRE-Agentic#subdirectory=agent

# 2. config
sudo mkdir -p /etc/sre-agent
sudo cp config.example.toml /etc/sre-agent/config.toml
sudo chmod 600 /etc/sre-agent/config.toml
# edit core_url; leave token empty to bootstrap

# 3. run (bootstrap: first successful register receives an issued token,
#    written back into config.toml automatically)
sudo sre-agent --config /etc/sre-agent/config.toml run

# 4. verify
curl $CORE_URL/api/servers             # new hostname, last_seen updating
```

systemd: `deploy/sre-agent.service` (expects `/usr/local/bin/sre-agent`).

Notes:
- outbound-only; agent never opens ports
- discovery runs every 5 min, collection every 30 s
- candidates appear unconfirmed in core UI → confirm before alerting
