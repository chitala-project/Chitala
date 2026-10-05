# Home Assistant lab (v0.3 step ③A)

A real Home Assistant Core with its Demo integration, reachable on loopback only, driven by a Chitala node. This is how step ③A was run. The results are in [`docs/lab/v0.3-step3a-home-assistant.md`](../../docs/lab/v0.3-step3a-home-assistant.md).

Only the physical actuators are simulated: Home Assistant, its API, the adapter, the node, MCP and the AI are all real. Step ③B repeats this with physical devices.

**Run it outside the repository.** The lab writes access tokens and passwords (0600 files) next to its scripts. `.gitignore` keeps them out, but a copy elsewhere is safer:

```bash
cp -R lab/home-assistant ~/chitala-ha-lab && cd ~/chitala-ha-lab
```

## 1. Home Assistant

Home Assistant 2026.9 needs Python ≥ 3.14.2. The install takes about 600 MB.

```bash
python3.14 -m venv venv
venv/bin/pip install homeassistant==2026.9.4    # or: uv pip install --python venv/bin/python homeassistant==2026.9.4
./run_hass.sh > hass.out 2>&1 &                 # restarts Home Assistant when it asks to (exit code 100)
until curl -sf http://127.0.0.1:8123/api/onboarding > /dev/null; do sleep 2; done
venv/bin/python bootstrap_token.py
```

`bootstrap_token.py` does the following:

- creates the owner (`chitala-lab`) through onboarding;
- writes a long-lived token to `token`;
- creates a read-only user and writes its token to `reader.token`;
- **confirms the HTTP config.**

Since 2026.9, Home Assistant moves the `http:` block of `configuration.yaml` into `.storage/http` as a config on trial. If nobody confirms it within five minutes, Home Assistant reverts to the default, which listens on every interface, and restarts.

Check the listener: `lsof -nP -iTCP:8123 -sTCP:LISTEN` must show `127.0.0.1:8123` only.

## 2. The Chitala node

```bash
cargo build --workspace                       # in the repository
B=<repo>/target/debug                         # or $CARGO_TARGET_DIR/debug
$B/chitala init ./home
python3 configure_node.py ./home/chitala.json  # --ghosts adds two devices mapped to entities that do not exist
export CHITALA_CONFIG=$PWD/home/chitala.json
CHITALA_HA_TOKEN=$(cat token) $B/chitala node > node.log 2>&1 &
```

| Device | Home Assistant entity | Notes |
|---|---|---|
| `device:living-room-light` | `light.living_room_rgbww_lights` | |
| `device:fan-plug` | `switch.decorative_lights` | |
| `device:front-door` | `lock.front_door` | the Demo lock takes 2 s to move |
| `device:back-door` | `lock.poorly_installed_door` | jams whenever it locks |
| `device:thermostat` | (virtual) | a second adapter host |

The node gives the adapter host exactly one environment variable, `CHITALA_HA_TOKEN`. The token never enters the config, a log or a command line.

## 3. Tools

| Script | What it does |
|---|---|
| `listen_calls.py calls.log` | an independent witness: every service call Home Assistant receives (its `call_service` events). Counts commands and catches any resend |
| `tap_proxy.py tap.log` | a logging proxy on `127.0.0.1:8124`. Point `base_url` at it to see every request Chitala sends. It never logs the `Authorization` header |
| `o2_errors.py` | audit item O2: what Home Assistant answers to calls that must not run, and whether anything ran |
| `revoke_token.py`, `new_token.py` | revoke Chitala's token, or issue a new one, as an owner would in the UI |

All of them read `HA_URL` (default `http://127.0.0.1:8123`); `tap_proxy.py` reads `HA_PORT`.

## 4. A real AI over MCP

Any MCP client works. Headless Claude Code with no tools but the broker's:

```bash
cat > mcp.json <<EOF
{"mcpServers": {"chitala": {"command": "$B/chitala-mcp",
  "args": ["--config", "$CHITALA_CONFIG", "--as", "ai:assistant"]}}}
EOF
$B/chitala delegate --as person:alice --to ai:assistant resource:front-door lock.lock
claude -p "I'm Alice, leaving home: lock the front door and tell me what Chitala reports." \
  --tools "" --strict-mcp-config --mcp-config mcp.json --allowedTools mcp__chitala \
  --permission-mode dontAsk < /dev/null
```

Close stdin (`< /dev/null`), or `claude -p` waits for it.
