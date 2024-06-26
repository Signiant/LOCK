import logging
import re

import paramiko

from project import values

logging.getLogger('paramiko').setLevel(logging.CRITICAL)


def SSH_server(hostname, username, port, commands, password=None, pkey=None, marker=None, markers=None):
    if port is None:
        port = 22
    logging.info('Attempting to connect to %s on port %s' % (hostname, str(port)))
    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy)

        if not pkey:
            logging.info('Authenticating with username (%s) and password' % username)
            client.connect(hostname, port=port, username=username, password=password, allow_agent=False, look_for_keys=False)
        else:
            k = paramiko.rsakey.RSAKey.from_private_key_file(pkey)
            logging.info('Authenticating with public key')
            client.connect(hostname, username=username, pkey=k)

        if markers is not None:  # Currently Azure only
            for i, mark in enumerate(markers):
                path = (commands[i].split()[-1])
                get_line = "sudo -- bash -c \"sed -n '/" + mark + "/=' " + path
                stdin, stdout, stderr = client.exec_command(get_line,get_pty=True)

                line_string = stdout.read().decode('utf-8')

                line=[s.strip() for s in line_string.splitlines()][0]  # remove \n and return first int
                line_num = int(line)
                commands[i] = commands[i].replace('<line>', str(line_num+1))

        if marker is not None:
            get_pty = False
            find_line_cmd = None
            if 'sudo' in commands[0]:
                # Needs to be run as root
                get_pty = True
                find_line_cmd = "echo '%s' | sudo -S sed -n '/%s/=' %s" % (password, marker, commands[0].split()[-1])
            else:
                find_line_cmd = "sed -n '/%s/=' %s" % (marker, commands[0].split()[-1])
            find_line_cmd = find_line_cmd.replace("\"", "")
            stdin, stdout, stderr = client.exec_command(find_line_cmd, get_pty=get_pty)

            output = (stdout.read().decode("utf-8"))
            logging.debug("Output from find_line_cmd: %s" % output)
            lines = re.search(r'\d+', output)
            if lines:
                line_num = int(lines.group())

                for i, command in enumerate(commands):
                    line_num += 1
                    commands[i] = command.replace('<line>', str(line_num))

        logging.info('Writing to '+hostname)
        for command in commands:
            command = command.replace("<q>", '\\"')

            if password is not None:
                command = command.replace('<password>', password)

            if values.DryRun is True:
                logging.info('Dry run, '+hostname+'| ssh command: '+command)
            else:
                try:
                    logging.debug('Running command: %s' % str(command))
                    stdin, stdout, stderr = client.exec_command(command,  get_pty=True)
                    stdout.read()
                    error = stderr.read()
                    if error:
                        logging.error('Error running command: %s' % error)
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
    list_of_commands = [command.replace("<new_key_name>", values.access_key[0].replace("/","\/")).replace("<new_key_secret>", values.access_key[1].replace("/","\/")) for command in list_of_commands]

    if key_args.get('pkey'):
        SSH_server(hostname=key_args.get('hostname'),
                   username=key_args.get('user'),
                   port=key_args.get('port'),
                   commands=list_of_commands,
                   pkey=key_args.get('pkey'),
                   markers=key_args.get('markers'),
                   marker=key_args.get('marker'))
    else:
        SSH_server(hostname=key_args.get('hostname'),
                   username=key_args.get('ssh_user'),
                   port=key_args.get('port'),
                   commands=list_of_commands,
                   password=key_args.get('ssh_password'),
                   marker=key_args.get('marker'),
                   markers=key_args.get('markers'))
