import logging
import re

import paramiko

from project import values

logging.getLogger('paramiko').setLevel(logging.CRITICAL)


def load_ssh_key(pkey_path, password=None):
    try:
        with open(pkey_path, 'r') as key_file:
            key_data = key_file.read()

        if "BEGIN RSA PRIVATE KEY" in key_data:
            return paramiko.RSAKey.from_private_key_file(pkey_path, password=password)
        elif "BEGIN OPENSSH PRIVATE KEY" in key_data:
            return paramiko.Ed25519Key.from_private_key_file(pkey_path, password=password)
        else:
            raise ValueError("Unsupported key format")
    except paramiko.PasswordRequiredException:
        logging.error("SSH key is encrypted and requires a passphrase.")
    except paramiko.SSHException as e:
        logging.error(f"Error loading SSH key: {e}")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
    return None


def find_line_number(client, file_path, marker, password=None):
    find_line_cmd = f"sed -n '/{marker}/=' {file_path}"
    if password:
        find_line_cmd = f"echo '{password}' | sudo -S {find_line_cmd}"

    stdin, stdout, stderr = client.exec_command(find_line_cmd, get_pty=True)
    output = stdout.read().decode("utf-8")
    logging.debug(f"Output from find_line_cmd: {output}")

    lines = re.findall(r'\d+', output)
    if lines:
        return int(lines[0])
    else:
        logging.error(f"No line number found for the marker: {marker}")
        return None


def update_env_vars(client, file_path, commands, markers, password=None):
    for i, marker in enumerate(markers):
        line_num = find_line_number(client, file_path, marker, password)
        if line_num is not None:
            commands[i] = commands[i].replace('<line>', str(line_num))
            logging.info(f"Updated command: {commands[i]}")
            stdin, stdout, stderr = client.exec_command(commands[i], get_pty=True)
            stdout.read()
            error = stderr.read()
            if error:
                logging.error(f"Error running command: {error}")


def ssh_server(hostname, username, port, commands, password=None, pkey=None, markers=None):
    if port is None:
        port = 22
    logging.info(f'Attempting to connect to {hostname} on port {port}')
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)

        if not pkey:
            logging.info(f'Authenticating with username ({username}) and password')
            client.connect(hostname, port=port, username=username, password=password, allow_agent=False,
                           look_for_keys=False)
        else:
            key = load_ssh_key(pkey, password)
            if key is None:
                logging.error("Failed to load the SSH key.")
                return
            logging.info('Authenticating with public key')
            client.connect(hostname, port=port, username=username, pkey=key)

        if markers is not None:
            update_env_vars(client, commands[0].split()[-1], commands, markers, password)

        logging.info(f'Executing commands on {hostname}')
        for command in commands:
            command = command.replace("<q>", '\\"')

            if password is not None:
                command = command.replace('<password>', password)

            if values.DryRun is True:
                logging.info(f'Dry run, {hostname} | ssh command: {command}')
            else:
                try:
                    logging.debug(f'Running command: {command}')
                    stdin, stdout, stderr = client.exec_command(command, get_pty=True)
                    stdout.read()
                    error = stderr.read()
                    if error:
                        logging.error(f'Error running command: {error}')
                except Exception as e:
                    logging.error(f'Failed to write key to {hostname} - {e}')
    except Exception as e:
        logging.error(f'Error with SSH connection: {e}')
        raise e
    finally:
        client.close()


# ssh and write to file using commands
def ssh_server_command(config_map, username, **key_args):
    list_of_commands = key_args.get('commands')
    list_of_commands = [
        command.replace("<new_key_name>", values.access_key[0].replace("/", "\/")).replace("<new_key_secret>",
                                                                                           values.access_key[1].replace(
                                                                                               "/", "\/")) for command
        in list_of_commands]

    if key_args.get('pkey'):
        ssh_server(hostname=key_args.get('hostname'),
                   username=key_args.get('user'),
                   port=key_args.get('port'),
                   commands=list_of_commands,
                   pkey=key_args.get('pkey'),
                   markers=key_args.get('markers'))
    else:
        ssh_server(hostname=key_args.get('hostname'),
                   username=key_args.get('ssh_user'),
                   port=key_args.get('port'),
                   commands=list_of_commands,
                   password=key_args.get('ssh_password'),
                   markers=key_args.get('markers'))
