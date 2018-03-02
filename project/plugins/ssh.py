from paramiko import SSHException
from scp import SCPClient

from project import values


def simpleScp():
    #https://github.com/jbardin/scp.py
    from paramiko import SSHClient
    ssh = SSHClient()
    ssh.load_system_host_keys()
    ssh.connect('', port=22, username="", password="")

    # SCPCLient takes a paramiko transport as its only argument
    # Just a no-op. Required sanitize function to allow wildcards.
    scp = SCPClient(ssh.get_transport())
    scp.get("/var/tmp/user*", "bak", recursive=True)

def SSH_server(hostname,  username, port, commands,password=None,  pkey=None): #https://gist.github.com/mlafeldt/841944
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

        for command in commands:
            stdin, stdout, stderr = client.exec_command(command)
            print (stdout.read())


    finally:
        client.close()

#unused, write only to yaml
def write_key_to_yaml(path, dictpath, newkey): #pass path, key ,key to write to,
    import yaml
    yamldict = yaml.load(open("/config/config.yaml"))
    yamldict['plugins']['key']= 'anewkey'
    yaml.dump(yamldict, open("/config/config.yaml", "w"), default_flow_style=False)
    return yaml.load(open("/config/config.yaml"))

#unused
def run_command(commands): #as list
    import subprocess
    subprocess.Popen(["ls", "-l"]) #handles common cases
    print (subprocess.check_output(['ls'])) #return as byte string

#write key to any file
def ssh_server_command(configMap, username,  **key_args): #https://stackoverflow.com/questions/11145270/how-to-replace-an-entire-line-in-a-text-file
    if  values.access_key==("",""):
        print('no key set, skipping ssh_server_command')
    else:
        from project.main import update_access_key
        update_access_key(('AKIAAAS','XXXXXXX'))

        list_of_commands=key_args.get('commands')
        list_of_commands=[ command.replace("<new_key_name>", values.access_key[0]).replace("<new_key_secret>", values.access_key[1]) for command in list_of_commands]

        if key_args.get('pkey') != None:
            response = SSH_server(hostname=key_args.get('hostname'), username=key_args.get('user'), port=key_args.get('port'), commands=list_of_commands, pkey=key_args.get('pkey'))
        else:
            response = SSH_server(hostname=key_args.get('hostname'), password=key_args.get('password'),  username=key_args.get('user'), port=key_args.get('port'), commands=list_of_commands)








    # GET COMMAND FROM YAML
    # STR.replace(<new_key_name>, new key)
    # RUN COMMAND response = SSH_server(command="sed -i '**LINE NUMBER**s/.*/**KEY PREFIX**<new_key_name>/' **FILE PATH**")

    #key id
    #response = SSH_server(command="sed -i '"+str(user_data['line_key'])+"s/.*/"+user_data['line_key_prefix']+str(new_key[0])+"/' "+user_data['filepath'])
    #secret
    #response = SSH_server(command="sed -i '"+str(user_data['line_secret'])+"s/.*/"+user_data['line_secret_prefix']+str(new_key[1])+"/' "+user_data['filepath'])
