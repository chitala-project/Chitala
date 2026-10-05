"""Chitala ③A lab: point the sample home of `chitala init` at Home Assistant's
Demo integration.

    python3 configure_node.py <home>/chitala.json [--ghosts] [--url http://127.0.0.1:8123]

- the living room light, the fan plug and the front door go through Home
  Assistant; the thermostat stays a virtual device (two adapter hosts);
- a back door is added on `lock.poorly_installed_door`, the Demo lock that
  jams whenever it locks;
- devices behind Home Assistant are SC1: Home Assistant cannot authenticate
  Chitala's command path (spec 10), and SC0 would forbid high-risk actions;
- `--ghosts` adds a lock and a light mapped to entities Home Assistant does not
  have, as a typo in a config would (finding F2).

The token is read by the node from CHITALA_HA_TOKEN; it never goes into the config.
"""

import argparse
import copy
import json

ENTITIES = {
    "device:living-room-light": "light.living_room_rgbww_lights",
    "device:fan-plug": "switch.decorative_lights",
    "device:front-door": "lock.front_door",
}


def clone(config, device_id, resource_id, new_device, new_resource, name, entity):
    device = copy.deepcopy(next(d for d in config["devices"] if d["id"] == device_id))
    device["id"], device["name"] = new_device, name
    config["devices"].append(device)
    resource = copy.deepcopy(next(r for r in config["resources"] if r["id"] == resource_id))
    resource["id"], resource["name"] = new_resource, name
    for binding in resource["bindings"]:
        binding["device"] = new_device
    resource["state"]["device"] = new_device
    config["resources"].append(resource)
    config["home_assistant"]["entities"][new_device] = entity


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("config")
    p.add_argument("--url", default="http://127.0.0.1:8123")
    p.add_argument("--ghosts", action="store_true")
    a = p.parse_args()
    config = json.load(open(a.config))
    for d in config["devices"]:
        if d["id"] in ENTITIES:
            d["adapter"], d["security_class"] = "home-assistant", "SC1"
    config["home_assistant"] = {"base_url": a.url, "token_env": "CHITALA_HA_TOKEN", "entities": dict(ENTITIES)}
    clone(config, "device:front-door", "resource:front-door", "device:back-door", "resource:back-door",
          "Back door", "lock.poorly_installed_door")
    if a.ghosts:
        clone(config, "device:front-door", "resource:front-door", "device:ghost-door", "resource:ghost-door",
              "Ghost door", "lock.ghost_door")
        clone(config, "device:living-room-light", "resource:living-room-light", "device:ghost-light",
              "resource:ghost-light", "Ghost light", "light.ghost_light")
    json.dump(config, open(a.config, "w"), indent=2)
    print(f"{a.config}: {len(config['home_assistant']['entities'])} devices through {a.url}")


if __name__ == "__main__":
    main()
