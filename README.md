# LOCK
Let's Occasionally Circulate Keys

A AWS key 

## Installing the Tool
- install python3.6 or higher
- pull the project from github 
- Install the required libraries if needed:  pip3 install -r /path/to/requirements.txt
- run from LOCK's root folder: python3 -m project.main -c "/path/to/config.yaml" -a rotate -u all

# Docker Usage

The easiest way to run the tool is from docker (because docker rocks).  You just pass it a team name and a config file and it will do everything from there

```bash
docker pull signiant/lock
```

```bash
docker run \
   -v /config/myconfigfile.yaml:/config.yaml \
   signiant/lock \
        -c /config.yaml \ 
```

In this example, we use a bindmount to mount in the config file from a local folder to the root directory of the container.  We can then pass the -c argument to the container to have it read the config from / and use the credentials from the config file.

There is an optional -d flag to the tool which will turn on more debug output.  For example:

```bash
docker run -ti \
   -v /config/myconfigfile.yaml:/config.yaml \
   signiant/lock \
        -c /config.yaml \
        -d
```

## How it works
LOCK has 4 main modes that accept the IAM user as an argument.

- list: Show user keys with: AccessKeyId, Status, CreateDate, Last Used.
- rotate: Bread and butter of the Tool. Rotates the AWS IAM key and updates key at predefined locations by running functions sequentially under plugins in the config file.
- validate: Checks to see if the new key is being used, if it is delete the old key
- getnewkey: If you only want to rotate the aws iam key.

## Typical Workflow
The tool runs functions sequentially in the order they appear for each different iam user in the config file. In the example below, the functions get_new_key and store_key_parameter_store are run from the iam module then the ssh_server_command is run from the ssh module. A typical key rotation scenario consists of deleting an old key and generating a new one (get_new_key), storing the key in the parameter store (store_key_parameter_store) then updating the key where the service uses the credential (ssh_server_command)
```

- iam_user1:
    plugins:
        - iam:
           - get_new_key:
           - store_key_parameter_store
        - ssh:
           - ssh_server_command: 
                  hostname: 'server1'
                  user: 'dev'
                  password: 'pw'
                  port: 22
                  commands: 
                      - "sed -i '1s/.*/aws_access_key_id = <new_key_name>/' /credentials-folder/credentials"
                      - "sed -i '2s/.*/aws_secret_access_key = <new_key_secret>/' /credentials-folder/credentials"
```
