from project import values

import logging
import paramiko
import re

logging.getLogger("paramiko").setLevel(logging.CRITICAL)


def load_ssh_key(username, pkey_path, password):
    try:
        with open(pkey_path, "r") as key_file:
            key_data = key_file.read()

        if "BEGIN RSA PRIVATE KEY" in key_data:
            return paramiko.RSAKey.from_private_key_file(pkey_path, password=password)
        elif "BEGIN OPENSSH PRIVATE KEY" in key_data:
            return paramiko.Ed25519Key.from_private_key_file(
                pkey_path, password=password
            )
        else:
            raise ValueError("Unsupported key format")
    except paramiko.PasswordRequiredException:
        logging.error(
            f"User {username}: SSH key is encrypted and requires a passphrase."
        )
    except paramiko.SSHException as e:
        logging.error(f"User {username}: Error loading SSH key: {e}")
    except Exception as e:
        logging.error(f"User {username}: Unexpected error: {e}")
    return None


def find_line_number(username, client, file_path, marker, password=None):
    find_line_cmd = f"sed -n '/{marker}/=' {file_path}"
    if password:
        find_line_cmd = f"echo '{password}' | sudo -S {find_line_cmd}"

    stdin, stdout, stderr = client.exec_command(find_line_cmd, get_pty=True)
    output = stdout.read().decode("utf-8")
    logging.debug(f"User {username}: Output from find_line_cmd: {output}")

    lines = re.findall(r"\d+", output)
    if lines:
        return int(lines[0])
    else:
        logging.error(f"User {username}: No line number found for the marker: {marker}")
        return None


def execute_command(username, client, command, password=None):
    command = command.replace("<q>", '\\"')

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


def update_env_vars(username, client, file_path, commands, markers, password=None):
    for i, marker in enumerate(markers):
        line_num = find_line_number(username, client, file_path, marker, password)
        if line_num is not None:
            commands[i] = commands[i].replace("<line>", str(line_num))
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
            connect_args = {}
            if password is not None:
                key = load_ssh_key(username, pkey, password)
                if key is None:
                    logging.error(
                        f"User {username}: Error connecting to {hostname}: Failed to load the SSH key at {pkey}"
                    )
                    return
                connect_args["pkey"] = key
            else:
                connect_args["key_filename"] = pkey
            logging.info(f"User {username}: Authenticating with public key")
            client.connect(hostname, port=port, username=ssh_username, **connect_args)

        if markers is not None:
            update_env_vars(
                username, client, commands[0].split()[-1], commands, markers, password
            )
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
            "<new_key_name>", values.access_keys[username][0].replace("/", "\/")
        ).replace(
            "<new_key_secret>", values.access_keys[username][1].replace("/", "\/")
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
