import logging
import shutil
from pathlib import Path
from typing import Optional

import click
import yaml
from google.protobuf.json_format import MessageToDict
from pywidevine.device import Device, DeviceTypes
from pywidevine.license_protocol_pb2 import FileHashes
from rich.prompt import Prompt
from unidecode import UnidecodeError, unidecode

from unshackle.core.config import config
from unshackle.core.console import console
from unshackle.core.constants import context_settings


@click.group(
    short_help="Manage configuration and creation of WVD (Widevine Device) files.", context_settings=context_settings
)
def wvd() -> None:
    """Manage configuration and creation of WVD (Widevine Device) files."""


@wvd.command()
@click.argument("paths", type=Path, nargs=-1)
def add(paths: list[Path]) -> None:
    """Add one or more WVD (Widevine Device) files to the WVDs Directory."""
    log = logging.getLogger("wvd")
    for path in paths:
        dst_path = config.directories.wvds / path.name

        if not path.exists():
            log.error(f"The WVD path '{path}' does not exist...")
        elif dst_path.exists():
            log.error(f"WVD named '{path.stem}' already exists...")
        else:
            # TODO: Check for and log errors
            _ = Device.load(path)  # test if WVD is valid
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(path, dst_path)
            log.info(f"Added {path.stem}")


@wvd.command()
@click.argument("names", type=str, nargs=-1)
def delete(names: list[str]) -> None:
    """Delete one or more WVD (Widevine Device) files from the WVDs Directory."""
    log = logging.getLogger("wvd")
    for name in names:
        path = (config.directories.wvds / name).with_suffix(".wvd")
        if not path.exists():
            log.error(f"No WVD file exists by the name '{name}'...")
            continue

        answer = Prompt.ask(
            f"[red]Deleting '{name}'[/], are you sure you want to continue?",
            choices=["y", "n"],
            default="n",
            console=console,
        )
        if answer == "n":
            log.info("Aborting...")
            continue

        Path.unlink(path)
        log.info(f"Deleted {name}")


@wvd.command()
@click.argument("path", type=Path)
def parse(path: Path) -> None:
    """
    Parse a .WVD Widevine Device file to check information.
    Relative paths are relative to the WVDs directory.
    """
    try:
        named = not path.suffix and path.relative_to(Path(""))
    except ValueError:
        named = False
    if named:
        path = config.directories.wvds / f"{path.name}.wvd"

    log = logging.getLogger("wvd")

    if not path.exists():
        console.log(f"[bright_blue]{path.absolute()}[/] does not exist...")
        return

    device = Device.load(path)

    log.info(f"System ID: {device.system_id}")
    log.info(f"Security Level: {device.security_level}")
    log.info(f"Type: {device.type}")
    log.info(f"Flags: {device.flags}")
    log.info(f"Private Key: {bool(device.private_key)}")
    log.info(f"Client ID: {bool(device.client_id)}")
    log.info(f"VMP: {bool(device.client_id.vmp_data)}")

    log.info("Client ID:")
    log.info(device.client_id)

    log.info("VMP:")
    if device.client_id.vmp_data:
        file_hashes = FileHashes()
        file_hashes.ParseFromString(device.client_id.vmp_data)
        log.info(str(file_hashes))
    else:
        log.info("None")


@wvd.command()
@click.argument("wvd_paths", type=Path, nargs=-1)
@click.argument("out_dir", type=Path, nargs=1)
def dump(wvd_paths: list[Path], out_dir: Path) -> None:
    """
    Extract data from a .WVD Widevine Device file to a folder structure.

    If the path is relative, with no file extension, it will dump the WVD in the WVDs
    directory.
    """
    log = logging.getLogger("wvd")

    if wvd_paths == ():
        if not config.directories.wvds.exists():
            console.log(f"[bright_blue]{config.directories.wvds.absolute()}[/] does not exist...")
        wvd_paths = list(x for x in config.directories.wvds.iterdir() if x.is_file() and x.suffix.lower() == ".wvd")
        if not wvd_paths:
            console.log(f"[bright_blue]{config.directories.wvds.absolute()}[/] is empty...")

    for i, (wvd_path, out_path) in enumerate(zip(wvd_paths, (out_dir / x.stem for x in wvd_paths))):
        if i > 0:
            log.info("")

        try:
            named = not wvd_path.suffix and wvd_path.relative_to(Path(""))
        except ValueError:
            named = False
        if named:
            wvd_path = config.directories.wvds / f"{wvd_path.stem}.wvd"
        out_path.mkdir(parents=True, exist_ok=True)

        log.info(f"Dumping: {wvd_path}")
        device = Device.load(wvd_path)

        log.info(f"L{device.security_level} {device.system_id} {device.type.name}")
        log.info(f"Saving to: {out_path}")

        device_meta = {
            "wvd": {"device_type": device.type.name, "security_level": device.security_level, **device.flags},
            "client_info": {},
            "capabilities": MessageToDict(device.client_id, preserving_proto_field_name=True)["client_capabilities"],
        }
        for client_info in device.client_id.client_info:
            device_meta["client_info"][client_info.name] = client_info.value

        device_meta_path = out_path / "metadata.yml"
        device_meta_path.write_text(yaml.dump(device_meta), encoding="utf8")
        log.info(" + Device Metadata")

        if device.private_key:
            private_key_path = out_path / "private_key.pem"
            private_key_path.write_text(data=device.private_key.export_key().decode(), encoding="utf8")
            private_key_path.with_suffix(".der").write_bytes(device.private_key.export_key(format="DER"))
            log.info(" + Private Key")
        else:
            log.warning(" - No Private Key available")

        if device.client_id:
            client_id_path = out_path / "client_id.bin"
            client_id_path.write_bytes(device.client_id.SerializeToString())
            log.info(" + Client ID")
        else:
            log.warning(" - No Client ID available")

        if device.client_id.vmp_data:
            vmp_path = out_path / "vmp.bin"
            vmp_path.write_bytes(device.client_id.vmp_data)
            log.info(" + VMP (File Hashes)")
        else:
            log.info(" - No VMP (File Hashes) available")


@wvd.command()
@click.argument("name", type=str)
@click.argument("private_key", type=Path)
@click.argument("client_id", type=Path)
@click.argument("file_hashes", type=Path, required=False)
@click.option(
    "-t",
    "--type",
    "type_",
    type=click.Choice([x.name for x in DeviceTypes], case_sensitive=False),
    default="Android",
    help="Device Type",
)
@click.option("-l", "--level", type=click.IntRange(1, 3), default=1, help="Device Security Level")
@click.option("-o", "--output", type=Path, default=None, help="Output Directory")
@click.pass_context
def new(
    ctx: click.Context,
    name: str,
    private_key: Path,
    client_id: Path,
    file_hashes: Optional[Path],
    type_: str,
    level: int,
    output: Optional[Path],
) -> None:
    """
    Create a new .WVD Widevine provision file.

    name: The origin device name of the provided data. e.g. `Nexus 6P`. You do not need to
        specify the security level, that will be done automatically.
    private_key: Device's RSA private key in PEM (PKCS#1 or PKCS#8) or DER format.
    client_id: A binary blob file which follows the Widevine ClientIdentification protobuf
        schema.
    file_hashes: A binary blob file with follows the Widevine FileHashes protobuf schema.
        Also known as VMP as it's used for VMP (Verified Media Path) assurance.
    """
    try:
        # TODO: Remove need for name, create name based on Client IDs ClientInfo values
        name = unidecode(name.strip().lower().replace(" ", "_"))
    except UnidecodeError as e:
        raise click.UsageError(f"name: Failed to sanitize name, {e}", ctx)
    if not name:
        raise click.UsageError("name: Empty after sanitizing, please make sure the name is valid.", ctx)
    if not private_key.is_file():
        raise click.UsageError("private_key: Not a path to a file, or it doesn't exist.", ctx)
    if not client_id.is_file():
        raise click.UsageError("client_id: Not a path to a file, or it doesn't exist.", ctx)
    if file_hashes and not file_hashes.is_file():
        raise click.UsageError("file_hashes: Not a path to a file, or it doesn't exist.", ctx)

    # Read the private key
    private_key_data = private_key.read_bytes()

    # Try to import the key - pywidevine supports PEM (PKCS#1/PKCS#8) and DER formats
    try:
        from Crypto.PublicKey import RSA

        # Test if the key can be imported
        RSA.import_key(private_key_data)
    except ValueError as e:
        # If import failed and the key doesn't have PEM headers, it might be base64-encoded PEM without headers
        if b"-----BEGIN" not in private_key_data:
            import base64

            # Check if it's base64-encoded (not binary DER)
            try:
                decoded = base64.b64decode(private_key_data, validate=True)
                # If successful, this might be base64-encoded DER or headerless PEM
                # Try importing as DER first
                try:
                    RSA.import_key(decoded)
                    private_key_data = decoded  # Use the decoded DER data
                except ValueError:
                    # Not DER, try adding PEM headers
                    # First try PKCS#1 format
                    private_key_data = (
                        b"-----BEGIN RSA PRIVATE KEY-----\n" + private_key_data + b"\n-----END RSA PRIVATE KEY-----"
                    )
                    try:
                        RSA.import_key(private_key_data)
                    except ValueError:
                        # Try PKCS#8 format
                        private_key_data = private_key.read_bytes()
                        private_key_data = (
                            b"-----BEGIN PRIVATE KEY-----\n" + private_key_data + b"\n-----END PRIVATE KEY-----"
                        )
                        RSA.import_key(private_key_data)  # Let this raise if it still fails
            except Exception:
                # Not base64, might be binary DER format - the original error is more helpful
                raise click.UsageError(
                    f"private_key: {e}. The private key must be in PEM (PKCS#1 or PKCS#8) or DER format.", ctx
                )
        else:
            raise click.UsageError(
                f"private_key: {e}. The private key must be in PEM (PKCS#1 or PKCS#8) or DER format.", ctx
            )

    device = Device(
        type_=DeviceTypes[type_.upper()],
        security_level=level,
        flags=None,
        private_key=private_key_data,
        client_id=client_id.read_bytes(),
    )

    if file_hashes:
        device.client_id.vmp_data = file_hashes.read_bytes()

    out_path = (output or config.directories.wvds) / f"{name}_{device.system_id}_l{device.security_level}.wvd"
    device.dump(out_path)

    log = logging.getLogger("wvd")

    log.info(f"Created binary WVD file, {out_path.name}")
    log.info(f" + Saved to: {out_path.absolute()}")

    log.info(f"System ID: {device.system_id}")
    log.info(f"Security Level: {device.security_level}")
    log.info(f"Type: {device.type}")
    log.info(f"Flags: {device.flags}")
    log.info(f"Private Key: {bool(device.private_key)}")
    log.info(f"Client ID: {bool(device.client_id)}")
    log.info(f"VMP: {bool(device.client_id.vmp_data)}")

    log.info("Client ID:")
    log.info(device.client_id)

    log.info("VMP:")
    if device.client_id.vmp_data:
        file_hashes = FileHashes()
        file_hashes.ParseFromString(device.client_id.vmp_data)
        log.info(str(file_hashes))
    else:
        log.info("None")


@wvd.command()
@click.argument("output", type=Path)
@click.option("--key-size", type=click.IntRange(2048, 4096), default=2048, help="RSA key size in bits")
def generate_key(output: Path, key_size: int) -> None:
    """
    Generate a new RSA private key in PEM format suitable for WVD creation.

    The generated key will be in PKCS#1 PEM format which is compatible
    with the 'wvd new' command.
    """
    from Crypto.PublicKey import RSA

    log = logging.getLogger("wvd")

    # Generate RSA key
    key = RSA.generate(key_size)

    # Export in PEM format
    private_key_pem = key.export_key(format="PEM")

    # Write to file
    output.write_bytes(private_key_pem)

    log.info(f"Generated {key_size}-bit RSA private key")
    log.info(f"Saved to: {output.absolute()}")
    log.info("Key format: PKCS#1 PEM")
    log.info(f"You can use this key with: unshackle wvd new <name> {output} <client_id>")
