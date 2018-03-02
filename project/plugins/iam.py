import boto3

from project import values


def get_iam_client(configMap):
    return boto3.client('iam',
                          aws_access_key_id=configMap['Global']['id'],
                          aws_secret_access_key=configMap['Global']['secret']
                          )

#RUN AS DEBUG
def create_and_test_key(configMap,username):
    client=get_iam_client(configMap)
    response = client.create_access_key(
        UserName=username
    )

    keyid=response.get('AccessKey').get('AccessKeyId')
    import time
    time.sleep(5)

    client2 =boto3.client('iam',
                          aws_access_key_id=response.get('AccessKey').get('AccessKeyId'),
                          aws_secret_access_key=response.get('AccessKey').get('SecretAccessKey')
                          )

    response = client2.list_access_keys(
        UserName=username
    )
    print(response)
    response=client.get_access_key_last_used(
        AccessKeyId=keyid
    )
    print(response)

def get_access_keys(client,username): #list of dictionary key metadata
    response = client.list_access_keys(UserName=username)
    print(response.get('AccessKeyMetadata'))
    return response.get('AccessKeyMetadata')

def delete_inactive_key(client, keys, username):
    for key in keys:
        response=key_last_used(client, key.get('AccessKeyId'))
        date=response.get('AccessKeyLastUsed').get('LastUsedDate')
        if date==None:
            client.delete_access_key(UserName=username, AccessKeyId=key.get('AccessKeyId'))
        if key.get('Status')=='Inactive':
            client.delete_access_key(UserName=username, AccessKeyId=key.get('AccessKeyId'))


def create_key(client,username):
    response = client.create_access_key(UserName=username)
    return (response.get('AccessKey').get('AccessKeyId'),response.get('AccessKey').get('SecretAccessKey'))

def delete_old_key(client,username,keyId):
    return client.delete_access_key( UserName = username, AccessKeyId = keyId)

def key_last_used(client, keyId):
   return  client.get_access_key_last_used(
        AccessKeyId=keyId
    )

def get_new_key(configMap, username,  **kwargs):
    if values.access_key==("",""): #run only if user hasnt manually entered a key
        from project.main import update_access_key
        # setup connection
        client = get_iam_client(configMap)

        # get existing keys
        oldkeys = get_access_keys(client, username)

        # delete 'inactive' keys and keys that have never been used (if any)
        delete_inactive_key(client, oldkeys, username)

        # create a new key
        new_key = create_key(client, username)
        print('New AccessKey: ' + str(new_key))
        update_access_key(new_key)
        return new_key

    #validate that new key is being used and delete the old unused key otherwise do nothing and advise the user
def validate_new_key(configMap,username):

    client=get_iam_client(configMap)
    keys=get_access_keys(client, username)

    lastUsed=[]
    for key in keys:
        response=key_last_used(client, key.get('AccessKeyId'))
        lastUsed.append(response)

    if keys[0].get('CreateDate')>keys[1].get('CreateDate'):  # get the most recently created key
        lastused = lastUsed[0].get('AccessKeyLastUsed').get('LastUsedDate')  # get the most recently created key's last used date
        n=0
    elif keys[1].get('CreateDate')>keys[0].get('CreateDate'):
        lastused = lastUsed[1].get('AccessKeyLastUsed').get('LastUsedDate')
        n=1

    if lastused is None:
        return ("New key has not been used. Check if service is properly running or if the key is properly assigned to the service.")
    else :
        print('New key in use, removing old key...')
        if n==0:
            delete_old_key(client, username, keys[1].get('AccessKeyId'))
        else:
            delete_old_key(client, username, keys[0].get('AccessKeyId'))
        return ('Old key was deleted.')

#add/overwrite
#http://boto3.readthedocs.io/en/latest/reference/services/ssm.html#SSM.Client.put_parameter

def store_key_parameter_store(  configMap, username,  **key_args ):

    client= boto3.client('ssm', aws_access_key_id=configMap['Global']['id'], aws_secret_access_key=configMap['Global']['secret'])

    response = client.get_parameter(Name=username,WithDecryption= True)

    response = client.put_parameter(
        Name=username,
        Description='modified by LOCK', #config desc
        Value='Key Id: '+ values.access_key[0]+' Secret Key: '+values.access_key[1],  # Key ID: XXXXXX Secret Key: XXXX
        Type='SecureString',
        Overwrite=True
    )

    print('Key written to parameter store.')

def list_keys(configMap,username):
    client=get_iam_client(configMap)
    keys=get_access_keys(client, username)
    for key in keys:
        response=(key_last_used(client,key.get('AccessKeyId')))
        key["Last Used"] =response.get('AccessKeyLastUsed').get('LastUsedDate')
        print('')
        for i in key:
            print (i, ':',key[i])

