import json
import os
import yaml


def load_policies(compiled_root: str):
    policies = []
    for root, _, files in os.walk(compiled_root):
        for name in files:
            if not (name.endswith(".yaml") or name.endswith(".yml") or name.endswith(".json")):
                continue
            path = os.path.join(root, name)
            with open(path, "r") as f:
                if name.endswith(".json"):
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
            if isinstance(data, dict) and "controls" in data and "enforcement" in data:
                policies.append(data)
    return policies


def main():
    compiled_root = os.path.join("releasegate", "policy", "compiled")
    out_path = os.path.join("forge", "src", "policies.json")
    policies = load_policies(compiled_root)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump({"policies": policies}, f, indent=2)
    print(f"Wrote {len(policies)} policies to {out_path}")


if __name__ == "__main__":
    main()
