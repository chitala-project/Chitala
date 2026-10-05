# Matter lab (v0.3 step ③A)

Virtual Matter devices from the Matter SDK, behind a real Home Assistant, driven by a Chitala node:

```text
Chitala → Home Assistant adapter → Home Assistant → Matter integration → OHF Matter Server (matter.js)
        → virtual light, plug and door lock (connectedhomeip v1.6.1.0 example apps)
```

The results are in [`docs/lab/v0.3-step3a-home-assistant.md`](../../docs/lab/v0.3-step3a-home-assistant.md), section *Matter*. Chitala is not changed to suit the simulators. The devices play external devices through the production interfaces, so a physical lock in step ③B changes nothing in Chitala.

It builds on the Home Assistant lab ([`../home-assistant`](../home-assistant/README.md)). The scripts expect the two labs side by side: `…/ha` and `…/matter`.

## 1. The Matter SDK (about 6 GB)

```bash
git clone --depth 1 --branch v1.6.1.0 https://github.com/project-chip/connectedhomeip.git
cd connectedhomeip
python3 scripts/checkout_submodules.py --shallow --platform darwin   # or linux
source scripts/bootstrap.sh -p all,darwin                            # Python 3.11 to 3.13
./scripts/build/build_examples.py --target darwin-arm64-light --target darwin-arm64-lock \
    --target darwin-arm64-all-devices --target darwin-arm64-chip-tool build
```

On Linux the targets are `linux-x64-…` (or `linux-arm64-…`).

## 2. The Matter server

Home Assistant 2026.9's Matter integration talks to the OHF Matter Server, which is built on matter.js. It needs Node.js 22.13 or later.

```bash
mkdir server && cd server && npm init -y && npm install matter-server@1.4.0
node node_modules/matter-server/dist/esm/MatterServer.js --storage-path "$PWD/storage" \
    --listen-address 127.0.0.1 --port 5580 --enable-test-net-dcl
```

`--enable-test-net-dcl` lets the server accept the SDK's **test** device certificates. That is acceptable in the lab only. For certified devices (step ③B) leave it off.

In Home Assistant, add the Matter integration with the URL `ws://127.0.0.1:5580/ws`. A config flow over the REST API works too.

## 3. The devices

```bash
./run_devices.sh start      # light :5541, plug :5542, lock :5543 (+ a named pipe)
./run_devices.sh codes      # their QR setup codes
<ha venv>/bin/python commission.py $(./run_devices.sh codes | awk '{print $1"="$2}')
```

Notes:

- **Commission by QR code.** The manual pairing code holds only the top 4 bits of the discriminator, so the three devices print the same one.
- **Give storage paths as absolute paths** (macOS keeps the SDK's storage under `~/Documents` otherwise). `run_devices.sh` does.
- **Wait before restarting a killed device.** It may not bind its port again for a minute (`TIME_WAIT`); `regression_matter.py` retries.
- **The lock takes simulated events on its pipe**, for example someone unlocking it by hand:

  ```bash
  echo '{"Cmd": "Unlock", "Params": {"EndpointId": 1, "OperationSource": 1}}' > state/lock.fifo
  ```

Home Assistant creates `light.test_product`, `switch.test_product` and `lock.test_product`. Then point Chitala at them:

```bash
python3 ../home-assistant/configure_node.py <home>/chitala.json \
    --matter light=light.test_product,plug=switch.test_product,lock=lock.test_product
```

## 4. Regression

```bash
CHITALA_BIN=$B CHITALA_CONFIG=<home>/chitala.json python3 regression_matter.py [--only 5,7]
```

It runs these scenarios:

- commands to the light, the plug and the lock, the lock's with approval;
- a lock moved by hand;
- a device that drops off;
- the controller lost;
- a device that dies right after a command.

Each is checked against Home Assistant, the device's own log and Chitala's audit.
