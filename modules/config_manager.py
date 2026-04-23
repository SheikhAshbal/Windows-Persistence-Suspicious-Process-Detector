"""
Config Manager
Saves and loads API keys from config.json — user enters once, never again.
"""

import os
import json

CONFIG_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")

DEFAULT_CONFIG = {
    "virustotal_api_key": "",
    "analyst_name": "",
}

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r") as f:
                data = json.load(f)
                # Merge with defaults in case new keys were added
                for k, v in DEFAULT_CONFIG.items():
                    if k not in data:
                        data[k] = v
                return data
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()

def save_config(config):
    with open(CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)

def get_virustotal_key():
    config = load_config()
    key = config.get("virustotal_api_key", "").strip()
    if key:
        return key

    print()
    print("[*] VirusTotal API Key not configured.")
    print("    Get a free key at: https://www.virustotal.com/gui/sign-in")
    print("    (Press Enter to skip — VT lookup will be disabled)")
    key = input("    API Key: ").strip()

    if key:
        config["virustotal_api_key"] = key
        save_config(config)
        print("    [*] API key saved to config.json — won't ask again.\n")
    else:
        print("    [*] Skipping VT lookup.\n")

    return key

def get_analyst_name():
    config = load_config()
    name = config.get("analyst_name", "").strip()
    if name:
        return name

    name = input("[*] Enter analyst name: ").strip() or "Analyst"
    config["analyst_name"] = name
    save_config(config)
    print(f"    [*] Name '{name}' saved to config.json — won't ask again.\n")
    return name

def reset_config():
    """Clear saved config — useful if user wants to change API key."""
    if os.path.exists(CONFIG_PATH):
        os.remove(CONFIG_PATH)
        print("[*] config.json deleted. Settings reset.")
    else:
        print("[*] No config.json found.")
