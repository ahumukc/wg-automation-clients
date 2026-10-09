import subprocess
from pathlib import Path
import configparser
import shutil
import re

BASE_DIR = Path(__file__).resolve().parent
CONFIG_NAME = "wgau.conf"
CONFIG_PATH = BASE_DIR / CONFIG_NAME
TEMPLATE_PATH = BASE_DIR / "templates" / CONFIG_NAME

def ensure_config() -> Path:
    if not CONFIG_PATH.exists():
        if not TEMPLATE_PATH.exists():
            raise FileNotFoundError(
                f"Not founded {CONFIG_PATH} and {TEMPLATE_PATH}"
            )
        shutil.copy(TEMPLATE_PATH, CONFIG_PATH)
        print(f"Config was created: {CONFIG_PATH}")
    return CONFIG_PATH

def ensure_wg_config(config: configparser.ConfigParser):
    if not Path(config["General"]["WIREGUARD_CONFIG_FILE"]).exists():
        raise FileNotFoundError(
            f"Wireguard config file not found on Path {config["General"]["WIREGUARD_CONFIG_FILE"]}"
        )

def load_config() -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH, encoding="utf-8")
    return config

def get_clients_dir(config: configparser.ConfigParser) -> Path:
    clients_path = Path(config["General"]["ABSALUTE_CLIENTS_FOLDER_PATH"]).expanduser().resolve()

    if not clients_path.is_absolute():
        raise ValueError(
            f"ABSALUTE_CLIENTS_FOLDER_PATH must be absolute, had: {clients_path}"
        )

    clients_dir = clients_path / "clients"
    clients_dir.mkdir(parents=True, exist_ok=True)
    return clients_dir


def get_next_client_number(clients_dir: Path, prefix: str) -> int:
    numbers = []
    for entry in clients_dir.iterdir():
        if entry.is_dir() and entry.name.startswith(prefix):
            suffix = entry.name.removeprefix(prefix)
            if suffix.isdigit():
                numbers.append(int(suffix))
    return max(numbers, default=0) + 1

def run_wg(args, stdin_data=None) -> str:
    result = subprocess.run(
        ["wg", *args],
        input=stdin_data,
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()

def generate_keys() -> dict:
    private_key = run_wg(["genkey"])
    public_key = run_wg(["pubkey"], private_key)
    psk = run_wg(["genpsk"])
    return {
        "private_key": private_key,
        "public_key": public_key,
        "psk": psk
    }

def parse_wg0(config: configparser.ConfigParser) -> dict:
    sections = []
    current = None
    for line in Path(config["General"]["WIREGUARD_CONFIG_FILE"]).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            current = {"name": line.strip("[]"), "params": {}}
            sections.append(current)
        elif "=" in line and current is not None:
            key, _, value = line.partition("=")
            current["params"][key.strip()] = value.strip()

    interface = next((s for s in sections if s["name"] == "Interface"), None)
    peers = [s for s in sections if s["name"] == "Peer"]
    return {"interface": interface, "peers": peers}

def get_server_public_key(config: configparser.ConfigParser) -> str:
    wg0 = parse_wg0(config)
    private_key = wg0["interface"]["params"].get("PrivateKey")
    if not private_key:
        raise ValueError("In wg0.conf there is no PrivateKey")
    return run_wg(["pubkey"], private_key)


def get_next_client_ip(config: configparser.ConfigParser) -> str:
    base = load_config()["Wireguard"]["ADDRESS_BASE"].strip()  # 10.0.0

    used = set()
    wg0 = parse_wg0(config)
    for peer in wg0["peers"]:
        allowed = peer["params"].get("AllowedIPs", "")
        for ip in allowed.split(","):
            ip = ip.strip().split("/")[0]
            m = re.fullmatch(rf"{re.escape(base)}\.(\d+)", ip)
            if m:
                used.add(int(m.group(1)))

    for i in range(2, 255):
        if i not in used:
            return f"{base}.{i}"
    raise RuntimeError("There are no free Ip")

def generate_client(clients_dir: Path, number: int,
                    client_prefix: str) -> Path:
    client_dir = clients_dir / f"{client_prefix}{number}"
    client_dir.mkdir(parents=True, exist_ok=True)

    keys = generate_keys()
    private_key = keys["private_key"]
    public_key = keys["public_key"]
    psk = keys["psk"]

    (client_dir / f"sec.key").write_text(private_key + "\n")
    (client_dir / f"pub.key").write_text(public_key + "\n")
    (client_dir / f"psk.key").write_text(psk + "\n")

    return client_dir

def main():
    ensure_config()
    config = load_config()

    ensure_wg_config(config)

    clients_dir = get_clients_dir(config)
    # number = get_next_client_number(clients_dir, config["Naming"]["CLIENT_PREFIX"])
    # client_dir = generate_client(clients_dir, number,
    #                             config["Naming"]["CLIENT_PREFIX"])
    # print(f"Client {number} generated in {client_dir}")

if __name__ == "__main__":
    main()