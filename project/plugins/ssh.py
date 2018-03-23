import logging
from project import values


def SSH_server(hostname,  username, port, commands,password=None,  pkey=None, marker=None, markers=None): #https://gist.github.com/mlafeldt/841944
    import paramiko

    try:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy)

        if pkey == None:
            client.connect(hostname, port=port, username=username, password=password)
        else:
            k = paramiko.RSAKey.from_private_key_file(pkey)
            client.connect(hostname,  username=username,  pkey=k)
        if markers is not None:
            #stdin, stdout, stderr = client.exec_command('sudo bash')
            for i, mark in enumerate(markers):
                path = (commands[i].split()[-1])  #get the file path of the command
                line = "sudo -- bash -c \"sed -n '/" + mark + "/=' " + path #+'"'
                stdin, stdout, stderr = client.exec_command(line,get_pty=True )

                # print(stderr.read())
                line_string = stdout.read().decode('utf-8')

                line=[s.strip() for s in line_string.splitlines()][0] # remove \n and return first int
                line_num = int(line)
                commands[i] = commands[i].replace('<line>', str(line_num+1))
                print('setting: '+commands[i])

            pass
        if marker is not None:
            line = "sed -n '/" + marker + "/=' " + (commands[0].split()[-1])
            stdin, stdout, stderr = client.exec_command(line)
            linu_num = int(stdout.read().decode("utf-8"))

            for i, command in enumerate(commands):
                linu_num += 1
                commands[i] = command.replace('<line>', str(linu_num))+"\'"

        for command in commands:

            command = command.replace("<q>",'\\"')
            stdin, stdout, stderr = client.exec_command(command,  get_pty=True)
            print('ran: ' + command)
            # print(command)
            print(stdout.read())
            print(stderr.read())

        logging.critical(username+" ssh succesfull")

    finally:
        client.close()

# unused, write only to yaml
# def write_key_to_yaml(path, dictpath, newkey): #pass path, key ,key to write to,
#     import yaml
#     yamldict = yaml.load(open("/config/config.yaml"))
#     yamldict['plugins']['key']= 'anewkey'
#     yaml.dump(yamldict, open("/config/config.yaml", "w"), default_flow_style=False)
#     return yaml.load(open("/config/config.yaml"))


# write key to any file
def ssh_server_command(configMap, username,  **key_args):
    if values.access_key == ("", ""):
        print('no key has been set, skipping ssh_server_command')
    else:
        list_of_commands = key_args.get('commands')
        list_of_commands = [command.replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>", values.access_key[1]) for command in list_of_commands]

        if key_args.get('pkey') != None:
            SSH_server(hostname=key_args.get('hostname'), username=key_args.get('user'), port=key_args.get('port'), commands=list_of_commands, pkey=key_args.get('pkey'), markers=key_args.get('markers') )
        else:
            SSH_server(hostname=key_args.get('hostname'), password=key_args.get('password'),  username=key_args.get('user'), port=key_args.get('port'), marker=key_args.get('marker'), commands=list_of_commands, markers=key_args.get('markers'))