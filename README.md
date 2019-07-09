# LOCK - Let's Occasionally Circulate Keys

From Signiant Operations comes LOCK. Lock allows you to change user credentials for AWS using a Python script.

# How It Works
LOCK has 4 main modes that accept an IAM user as an argument or from a YAML configuration file using `-c`.

- `list`: Show user keys with: Access Key ID, Status, Create Date, Last Used.
- `rotate`: Rotates the AWS IAM key and update the key at set locations by running functions sequentially under plugins provided by the config file.
- `validate`: Checks to see if the new key is being used, if it is delete the old key
- `getnewkey`: Rotate the AWS IAM Key

## Up and Running

- Install Python 3.6 or higher
- Clone this repository
- Run  `pip3 install -r /project/config/requirements.txt` to install the dependencies
- Run from LOCK's root folder

#
## Running LOCK from the Command Line

To rotate keys from the command line, use `python3` to run the main script.
the config.yaml could be retrived from another signiant devops engineer.
The config.yaml file need to be modified before used.

```bash
$ python3 -m main.py -c "/path/to/config.yaml" -a rotate -u all
```

## Running LOCK using Docker 🐳

Pull the docker container:

```bash
docker pull signiant/lock
```

Run LOCK using a configuration file:

```bash
docker run \
   -v /config/config.yaml:/config.yaml \
   signiant/lock \
        -c /config.yaml \ 
```

In this example, we use `-v` to mount `config.yaml` from a local folder to the root directory of the container, then pass the `-c` to read and use credentials from the configuration file.

## Debugging
Use the `-d` flag to the tool which will turn on more debug output:

```bash
docker run -ti \
   -v /config/myconfigfile.yaml:/config.yaml \
   signiant/lock \
        -c /config.yaml \
        -d
```

## Typical Workflow
The tool runs functions sequentially in the order they appear for each different IAM user in the config file.

A typical key rotation scenario consists of deleting an old key and generating a new one (get_new_key), storing the key in the parameter store (store_key_parameter_store) then updating the key where the service uses the credential (ssh_server_command)

In the `get_new_key` and `store_key_parameter_store` run from the IAM module, then the `ssh_server_command` is run from the SSH module.

```

- iam_user1:
    plugins:
        - iam:
           - get_new_key:
           - store_key_parameter_store
        - ssh:
           - ssh_server_command: 
                  hostname: 'your_ssh_server'
                  user: 'user_name'
                  password: 'super_secure_password'
                  port: 22
                  commands: 
                      - "sed -i '1s/.*/aws_access_key_id = <new_key_name>/' /credentials-folder/credentials"
                      - "sed -i '2s/.*/aws_secret_access_key = <new_key_secret>/' /credentials-folder/credentials"
```
