from project import values

import base64
import logging
import nacl.signing
import paramiko
import re

logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def _asn1_read_len(data, i):
    first = data[i]
    i += 1
    if first & 0x80 == 0:
        return first, i
    n = first & 0x7F
    return int.from_bytes(data[i : i + n], "big"), i + n


def _load_ed25519_pkcs8_v2(pem_text):
    """
    1Password exports unencrypted Ed25519 keys as an RFC 5958 v2
    OneAsymmetricKey, which appends an optional public-key field after the
    standard PKCS#8 version/algorithm/privateKey fields. OpenSSL parses this
    fine, but the `cryptography` release paramiko's PKey.from_path() relies
    on rejects it as "extra data". Pull the raw 32-byte seed out ourselves
    to sidestep that parser.
    """
    body = "".join(
        line.strip()
        for line in pem_text.splitlines()
        if line and "BEGIN" not in line and "END" not in line
    )
    der = base64.b64decode(body)

    i = 1
    _, i = _asn1_read_len(der, i)  # outer SEQUENCE header
    length, i = _asn1_read_len(der, i + 1)  # version (INTEGER)
    i += length
    length, i = _asn1_read_len(der, i + 1)  # algorithm identifier (SEQUENCE)
    i += length
    length, i = _asn1_read_len(der, i + 1)  # privateKey (OCTET STRING)
    octet_string = der[i : i + length]
    inner_length, inner_start = _asn1_read_len(octet_string, 1)
    seed = octet_string[inner_start : inner_start + inner_length]

    signing_key = nacl.signing.SigningKey(seed)
    key = paramiko.Ed25519Key.__new__(paramiko.Ed25519Key)
    key.public_blob = None
    key._signing_key = signing_key
    key._verifying_key = signing_key.verify_key
    return key


def load_ssh_key(username, pkey_path, password):
    try:
        return paramiko.PKey.from_path(pkey_path, passphrase=password)
    except ValueError as e:
        if password is None and "extra data" in str(e).lower():
            try:
                with open(pkey_path, "r") as key_file:
                    pem_text = key_file.read()
                if "BEGIN PRIVATE KEY" in pem_text:
                    return _load_ed25519_pkcs8_v2(pem_text)
            except Exception:
                pass
        logging.error(f"User {username}: Unexpected error: {e}")
    except paramiko.PasswordRequiredException:
        logging.error(
            f"User {username}: SSH key is encrypted and requires a passphrase."
        )
    except paramiko.SSHException as e:
        logging.error(f"User {username}: Error loading SSH key: {e}")
    except Exception as e:
        logging.error(f"User {username}: Unexpected error: {e}")
    return None


def find_line_number(username, client, file_path, marker, password=None, sudo_cmd=False):
    logging.debug(f'User {username}: Determining line number for sed command')
    find_line_cmd = f"sed -n '/{marker}/=' {file_path}"
    if sudo_cmd:
        logging.debug(f'prefacing sed command with sudo')
        find_line_cmd = f"sudo {find_line_cmd}"
    else:
        if password:
            find_line_cmd = f"echo '{password}' | sudo -S {find_line_cmd}"

    # TODO: the find_line_cmd can have a secret in it - logging debug to file - redact if hidekey is true?
    logging.debug(f'User {username}: find_line_cmd: {find_line_cmd}')
    stdin, stdout, stderr = client.exec_command(find_line_cmd, get_pty=True)
    output = stdout.read().decode("utf-8")
    exit_code = stdout.channel.recv_exit_status()
    logging.debug(f"User {username}: Output from find_line_cmd: {output}")
    
    if exit_code != 0:
        logging.error(f"User {username}: Command failed with exit code {exit_code}: {output.strip()}")
        return None

    lines = re.findall(r"\d+", output)
    if lines:
        return int(lines[0])
    else:
        logging.error(f"User {username}: No line number found for the marker: {marker}")
        return None


def execute_command(username, client, command, password=None):
    if password is not None:
        command = command.replace("<password>", password)

    if values.DryRun is True:
        logging.info(f"User {username}: Dry run, command: {command}")
    else:
        try:
            logging.debug(f"User {username}: Running command: {command}")
            stdin, stdout, stderr = client.exec_command(command, get_pty=True)
            stdout.read()
            error = stderr.read()
            if error:
                logging.error(f"User {username}: Error running command: {error}")
        except Exception as e:
            logging.error(f"User {username}: Failed to execute command - {e}")


def update_env_vars(username, client, commands, markers, password=None):
    for i, marker in enumerate(markers):
        sudo_cmd = False
        if commands[i].startswith('sudo'):
            sudo_cmd = True
        file_path = commands[i].split()[-1].rstrip('"')
        line_num = find_line_number(username, client, file_path, marker, password, sudo_cmd)
        if line_num is not None:
            commands[i] = commands[i].replace("<line>", str(line_num))
            if 'secret' not in commands[i].lower():
                logging.info(f"User {username}: Updated command: {commands[i]}")
            else:
                if values.hide_key is True:
                    # TODO: create an actual function to redact ONLY the secret text
                    logging.info(f"User {username}: Updated command: <redacted>")
                else:
                    logging.info(f"User {username}: Updated command: {commands[i]}")
            execute_command(username, client, commands[i], password)


def ssh_server(
    username,
    hostname,
    ssh_username,
    port,
    commands,
    password=None,
    pkey=None,
    markers=None,
):
    if port is None:
        port = 22
    logging.info(f"User {username}: Attempting to connect to {hostname} on port {port}")
    client = None
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)

        if not pkey:
            logging.info(
                f"User {username}: Authenticating with username ({ssh_username}) and password"
            )
            client.connect(
                hostname,
                port=port,
                username=ssh_username,
                password=password,
                allow_agent=False,
                look_for_keys=False,
            )
        else:
            key = load_ssh_key(username, pkey, password)
            if key is None:
                logging.error(
                    f"User {username}: Error connecting to {hostname}: Failed to load the SSH key at {pkey}"
                )
                return
            logging.info(f"User {username}: Authenticating with public key")
            client.connect(
                hostname, port=port, username=ssh_username, pkey=key
            )

        if markers is not None:
            update_env_vars(username, client, commands, markers, password)
        else:
            logging.info(f"User {username}: Executing commands on {hostname}")
            for command in commands:
                execute_command(username, client, command, password)
    except Exception as e:
        logging.error(f"User {username}: Error with SSH connection: {e}")
    finally:
        if client is not None:
            client.close()


# ssh and write to file using commands
def ssh_server_command(_, username, **key_args):
    list_of_commands = key_args.get("commands")
    list_of_commands = [
        command.replace(
            "<new_key_name>", values.access_keys[username][0]
        ).replace(
            "<new_key_secret>", values.access_keys[username][1]
        )
        for command in list_of_commands
    ]

    if key_args.get("pkey"):
        ssh_server(
            username,
            hostname=key_args.get("hostname"),
            ssh_username=key_args.get("user"),
            port=key_args.get("port"),
            commands=list_of_commands,
            pkey=key_args.get("pkey"),
            markers=key_args.get("markers"),
        )
    else:
        ssh_server(
            username,
            hostname=key_args.get("hostname"),
            ssh_username=key_args.get("ssh_user"),
            port=key_args.get("port"),
            commands=list_of_commands,
            password=key_args.get("ssh_password"),
            markers=key_args.get("markers"),
        )
