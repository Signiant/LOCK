# LOCK
Let's Occasionally Circulate Keys

A AWS key 

## Installing the Tool
 1. Install python 3 or higher
 2. Install LOCK with pip:
 >     sudo pip3 install lock-key-rotation
 3. Run the tool anywhere using the new console script "lock" with required arguments.
 >     lock -c 'pathtofile/config.yaml' -u iamuser -m rotate

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
