import subprocess
from pathlib import Path
import configparser
import shutil

BASE_DIR = Path(__file__).resolve().parent
CONFIG_NAME = "wgau_autogen.conf"
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

import subprocess


def run_wg(args, stdin_data=None) -> str:
    result = subprocess.run(
        ["wg", *args],
        input=stdin_data,
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()


def generate_client(clients_dir: Path, number: int,
                    client_prefix: str, file_prefix: str) -> Path:
    client_dir = clients_dir / f"{client_prefix}{number}"
    client_dir.mkdir(parents=True, exist_ok=True)

    private_key = run_wg(["genkey"])
    public_key = run_wg(["pubkey"], private_key)
    psk = run_wg(["genpsk"])

    p = f"{file_prefix}{number}"
    (client_dir / f"sec_{p}.key").write_text(private_key + "\n")
    (client_dir / f"pub_{p}.key").write_text(public_key + "\n")
    (client_dir / f"psk_{p}.key").write_text(psk + "\n")

    return client_dir

def main():
    ensure_config()
    config = load_config()
    clients_dir = get_clients_dir(config)
    number = get_next_client_number(clients_dir, config["Naming"]["CLIENT_PREFIX"])
    client_dir = generate_client(clients_dir, number,
                                config["Naming"]["CLIENT_PREFIX"],
                                config["Naming"]["FILE_PREFIX"])
    print(f"Client {number} generated in {client_dir}")

if __name__ == "__main__":
    main()