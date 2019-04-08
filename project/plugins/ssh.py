import logging
import paramiko
import re
from project import values


def SSH_server(hostname, username, port, commands, password=None, pkey=None, marker=None, markers=None): # https://gist.github.com/mlafeldt/841944

    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy)

        if not pkey:
            logging.info('Authenticating with username and password')
            client.connect(hostname, port=port, username=username, password=password, allow_agent=False, look_for_keys=False)
        else:
            k = paramiko.RSAKey.from_private_key_file(pkey)
            logging.info('Authenticating with public key')
            client.connect(hostname,  username=username,  pkey=k)

        if markers is not None: # Currently Azure only
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
                find_line_cmd = "echo %s | sudo -S sed -n '/%s/=' %s" % (password, marker, commands[0].split()[-1])
            else:
                find_line_cmd = "sed -n '/%s/=' %s" % (marker, commands[0].split()[-1])
            find_line_cmd = find_line_cmd.replace("\"", "")
            stdin, stdout, stderr = client.exec_command(find_line_cmd, get_pty=get_pty)

            output = (stdout.read().decode("utf-8"))
            line_num = int(re.search(r'\d+', output).group())

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
                        logging.error('Error runnng command: %s' % error)
                except:
                    logging.error('Failed to write key to '+hostname)

    finally:
        client.close()


# ssh and write to file using commands
def ssh_server_command(configMap, username,  **key_args):
        if (key_args.get('hostname') in configMap['Global']['server']):
            auth=configMap['Global']['server'][key_args.get('hostname')]
            key_args['user'] = auth.get('user')
            key_args['password'] = auth.get('password')

        list_of_commands = key_args.get('commands')
        list_of_commands = [command.replace("<new_key_name>", values.access_key[0].replace("/","\/")).replace("<new_key_secret>", values.access_key[1].replace("/","\/")) for command in list_of_commands]

        if key_args.get('pkey') != None:
            SSH_server(hostname=key_args.get('hostname'), username=key_args.get('user'), port=key_args.get('port'), commands=list_of_commands, pkey=key_args.get('pkey'), markers=key_args.get('markers'),marker= key_args.get('marker'))
        else:
            SSH_server(hostname=key_args.get('hostname'), password=key_args.get('password'),  username=key_args.get('user'), port=key_args.get('port'), marker=key_args.get('marker'), commands=list_of_commands, markers=key_args.get('markers'))
