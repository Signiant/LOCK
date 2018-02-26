import boto3

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

def get_client(configMap,name): #name!=Global
    return boto3.client('iam', aws_access_key_id=configMap['Global']['id'], aws_secret_access_key=configMap['Global']['secret'])

def get_access_keys(client,username): #list of dictionary key metadata
    response = client.list_access_keys(UserName=username)
    print(response.get('AccessKeyMetadata'))
    return response.get('AccessKeyMetadata')

def delete_inactive_key(client, keys, username):
    for key in keys:
        if key.get('Status')=='Inactive':
            return client.delete_access_key(UserName=username, AccessKeyId=key.get('AccessKeyId'))


def create_key(client,username):
    response = client.create_access_key(UserName=username)
    return (response.get('AccessKey').get('AccessKeyId'),response.get('AccessKey').get('SecretAccessKey'))

def delete_old_key(client,username,keyId):
    return client.delete_access_key( UserName = username, AccessKeyId = keyId)

def key_last_used(client, keyId):
   return  client.get_access_key_last_used(
        AccessKeyId=keyId
    )

def key_rotation():
    pass

    #validate that new key is being used and delete unused key

def validate_new_key(configMap,username):

    client=get_iam_client(configMap)
    keys=get_access_keys(client, username)
    print(keys)

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
        return ("New key has not been used. Check if service is properly running or if the service is properly assigned the new key.")
    else :
        print('removing old key...')
        if n==0:
            delete_old_key(client, username, keys[1].get('AccessKeyId'))
        else:
            delete_old_key(client, username, keys[0].get('AccessKeyId'))
        return ('Old key was deleted.')


