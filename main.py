import subprocess
from pathlib import Path
import configparser
import shutil
import re
from string import Template
import argparse

try:
    import qrcode
except ImportError:
    raise RuntimeError(
        "qrcode is not installed. Run: pip install qrcode[pil]"
    )

BASE_DIR = Path(__file__).resolve().parent
CONFIG_NAME = "wgau.conf"
CONFIG_PATH = BASE_DIR / CONFIG_NAME
TEMPLATE_PATH = BASE_DIR / "templates" / CONFIG_NAME

CLIENT_TEMPLATE_PATH = BASE_DIR / "templates" / "client.conf"


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
    base = config["Wireguard"]["ADDRESS_BASE"].strip()  # 10.0.0

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

def render_client_conf(keys: dict, client_ip: str,
                       config: configparser.ConfigParser) -> str:
    template = Template(CLIENT_TEMPLATE_PATH.read_text(encoding="utf-8"))
    return template.substitute(
        private_key=keys["private_key"],
        client_ip=client_ip,
        server_public_key=get_server_public_key(config),
        psk=keys["psk"],
        endpoint=config["Wireguard"]["ENDPOINT"],
        dns=config["Wireguard"]["DNS_SERVER"],
    )

def add_peer_to_wg0(config: configparser.ConfigParser, client_name: str,
                    public_key: str, psk: str, client_ip: str) -> None:
    wg_path = Path(config["General"]["WIREGUARD_CONFIG_FILE"])
    content = wg_path.read_text(encoding="utf-8")

    if f"# BEGIN_PEER {client_name}\n" in content:
        raise ValueError(f"Peer {client_name} already exists in {wg_path}")

    peer_block = (
        f"# BEGIN_PEER {client_name}\n"
        f"[Peer]\n"
        f"PublicKey = {public_key}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {client_ip}/32\n"
        f"# END_PEER {client_name}\n"
    )

    new_content = content.rstrip("\n") + "\n\n" + peer_block
    tmp = wg_path.with_suffix(".conf.tmp")
    tmp.write_text(new_content, encoding="utf-8")
    tmp.replace(wg_path)

def create_client_folder(clients_dir: Path, client_name: str, keys: dict,
                         client_ip: str,
                         config: configparser.ConfigParser) -> Path:
    client_dir = clients_dir / client_name
    client_dir.mkdir(parents=True, exist_ok=True)

    (client_dir / "sec.key").write_text(keys["private_key"] + "\n")
    (client_dir / "pub.key").write_text(keys["public_key"] + "\n")
    (client_dir / "psk.key").write_text(keys["psk"] + "\n")

    conf_path = client_dir / "client.conf"
    conf_path.write_text(render_client_conf(keys, client_ip, config),
                         encoding="utf-8")

    qr_path = generate_client_qr(client_dir, client_name)

    for f in client_dir.iterdir():
        f.chmod(0o600)

    return client_dir

def get_taken_client_names(config: configparser.ConfigParser) -> set[str]:
    taken = set()

    for peer in get_peers_info(config):
        if peer["name"] is not None:
            taken.add(peer["name"])

    clients_dir = get_clients_dir(config)
    prefix = config["Naming"]["CLIENT_PREFIX"]
    for entry in clients_dir.iterdir():
        if entry.is_dir() and entry.name.startswith(prefix):
            taken.add(entry.name)

    return taken

def get_next_client_name(config: configparser.ConfigParser) -> str:
    prefix = config["Naming"]["CLIENT_PREFIX"]
    taken = get_taken_client_names(config)

    n = 1
    while f"{prefix}{n}" in taken:
        n += 1
    return f"{prefix}{n}"

def get_peers_info(config: configparser.ConfigParser) -> list[dict]:
    wg_path = Path(config["General"]["WIREGUARD_CONFIG_FILE"])
    peers = []
    current = None

    for line in wg_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()

        m = re.fullmatch(r"#\s*BEGIN_PEER\s+(\S+)", stripped)
        if m:
            current = {"name": m.group(1), "params": {}}
            peers.append(current)
            continue

        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("[") and stripped.endswith("]"):
            if stripped == "[Peer]":
                if current is None:
                    current = {"name": None, "params": {}}
                    peers.append(current)
            else:
                current = None
            continue

        if "=" in stripped and current is not None:
            key, _, value = stripped.partition("=")
            current["params"][key.strip()] = value.strip()

    return peers

def add_folders_for_existing_peers(config: configparser.ConfigParser) -> int:
    clients_dir = get_clients_dir(config)
    prefix = config["Naming"]["CLIENT_PREFIX"]
    created = 0

    for peer in get_peers_info(config):
        name = peer["name"]

        if name is None:
            allowed = peer["params"].get("AllowedIPs", "")
            ip = allowed.split(",")[0].strip().split("/")[0]
            name = f"{prefix}_{ip.rsplit('.', 1)[-1]}"
            print(f"Warning: peer {ip} has no BEGIN_PEER marker, "
                  f"using folder name '{name}'")

        client_dir = clients_dir / name
        if client_dir.exists():
            continue

        client_dir.mkdir(parents=True)

        params = peer["params"]
        if "PublicKey" in params:
            (client_dir / "pub.key").write_text(params["PublicKey"] + "\n")
        if "PresharedKey" in params:
            (client_dir / "psk.key").write_text(params["PresharedKey"] + "\n")

        for f in client_dir.iterdir():
            f.chmod(0o600)

        print(f"Folder created: {client_dir}")
        if "PrivateKey" not in params:
            print(f"  Note: private key for {name} is unknown, "
                  f"client.conf was NOT generated. "
                  f"Put sec.key into the folder and run 'conf' command.")
        created += 1

    return created

def add_client(config: configparser.ConfigParser) -> None:
    clients_dir = get_clients_dir(config)

    client_name = get_next_client_name(config)

    keys = generate_keys()
    client_ip = get_next_client_ip(config)

    add_peer_to_wg0(config, client_name, keys["public_key"],
                    keys["psk"], client_ip)
    client_dir = create_client_folder(clients_dir, client_name, keys,
                                      client_ip, config)

    print(f"Client {client_name} generated in {client_dir}")
    print(f"  IP:     {client_ip}")
    print(f"  Config: {client_dir / 'client.conf'}")

def generate_conf_from_sec(client_dir: Path,
                           config: configparser.ConfigParser) -> Path:
    sec = client_dir / "sec.key"
    if not sec.exists():
        raise FileNotFoundError(f"{sec} not found")

    private_key = sec.read_text().strip()
    public_key = run_wg(["pubkey"], private_key)

    expected_pub = client_dir / "pub.key"
    if expected_pub.exists() and expected_pub.read_text().strip() == public_key:
        raise ValueError(f"sec.key in {client_dir} does not match pub.key")

    peer = next(
        (p for p in get_peers_info(config) if p["name"] == client_dir.name),
        None
    )
    if peer is None:
        raise ValueError(
            f"Peer '{client_dir.name}' not found in wg0.conf — "
            f"cannot determine client IP"
        )

    allowed = peer["params"].get("AllowedIPs", "")
    if not allowed:
        raise ValueError(f"Peer {client_dir.name} has no AllowedIPs in wg0.conf")
    client_ip = allowed.split(",")[0].strip().split("/")[0]

    keys = {
        "private_key": private_key,
        "public_key": public_key,
        "psk": peer["params"].get("PresharedKey", ""),
    }

    conf = client_dir / "client.conf"
    conf.write_text(render_client_conf(keys, client_ip, config), encoding="utf-8")
    conf.chmod(0o600)
    return conf

def generate_client_qr(client_dir: Path, client_name: str) -> Path:
    conf_path = client_dir / "client.conf"
    img = qrcode.make(conf_path.read_text(encoding="utf-8"))
    qr_path = client_dir / f"{client_name}.png"
    img.save(qr_path)
    return qr_path

def show_client_qr(client_dir: Path) -> None:
    conf_path = client_dir / "client.conf"
    if not conf_path.exists():
        raise FileNotFoundError(f"{conf_path} not found")

    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        border=1,
    )
    qr.add_data(conf_path.read_text(encoding="utf-8"))
    qr.print_ascii(invert=True)

def main():
    ensure_config()
    config = load_config()
    ensure_wg_config(config)

    parser = argparse.ArgumentParser(description="WireGuard client manager")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("add", help="Add new client (keys + folder + peer in wg0.conf)")
    sub.add_parser("sync", help="Create folders for existing peers from wg0.conf")

    show = sub.add_parser("show", help="Generate and show QR code for client")
    show.add_argument("client_name", help="Client name, e.g. client1")

    conf_cmd = sub.add_parser("conf", help="Generate client.conf from existing sec.key")
    conf_cmd.add_argument("client_name", help="Client name, e.g. client1")

    args = parser.parse_args()

    if args.command == "add":
        add_client(config)
    elif args.command == "sync":
        created = add_folders_for_existing_peers(config)
        print(f"Created {created} folder(s)")
    elif args.command == "show":
        show_client_qr(get_clients_dir(config) / args.client_name)
    elif args.command == "conf":
        generate_conf_from_sec(get_clients_dir(config) / args.client_name, config)


if __name__ == "__main__":
    main()