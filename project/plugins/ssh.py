from scp import SCPClient


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

def SSH_server(hostname, password, command, username, port): #https://gist.github.com/mlafeldt/841944
    try:
        import paramiko
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.WarningPolicy)

        client.connect(hostname, port=port, username=username, password=password)
        stdin, stdout, stderr = client.exec_command(command)
        print (stdout.read())
        return(stdout.read())

    finally:
        client.close()

#unused, write only to yaml
def write_key_to_yaml(path, dictpath, newkey): #pass path, key ,key to write to,
    import yaml
    yamldict = yaml.load(open("/Users/elaroche/PycharmProjects/LOCK/project/config/config.yaml"))
    yamldict['plugins']['key']= 'anewkey'
    yaml.dump(yamldict, open("/Users/elaroche/PycharmProjects/LOCK/project/config/config.yaml", "w"), default_flow_style=False)
    return yaml.load(open("/Users/elaroche/PycharmProjects/LOCK/project/config/config.yaml"))

#unused
def run_command(commands): #as list
    import subprocess
    subprocess.Popen(["ls", "-l"]) #handles common cases
    print (subprocess.check_output(['ls'])) #return as byte string

#write key to any file
def write_new_key(user_data,new_key): #https://stackoverflow.com/questions/11145270/how-to-replace-an-entire-line-in-a-text-file
    #key id
    response = SSH_server(command="sed -i '"+str(user_data['line_key'])+"s/.*/"+user_data['line_key_prefix']+str(new_key[0])+"/' "+user_data['filepath'])
    #secret
    response = SSH_server(command="sed -i '"+str(user_data['line_secret'])+"s/.*/"+user_data['line_secret_prefix']+str(new_key[1])+"/' "+user_data['filepath'])
