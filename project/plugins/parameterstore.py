
#add/overwrite
#http://boto3.readthedocs.io/en/latest/reference/services/ssm.html#SSM.Client.put_parameter

import boto3

def insert_parameter( new_key, username, configMap):
    client= boto3.client('ssm', aws_access_key_id=configMap['Global']['id'], aws_secret_access_key=configMap['Global']['secret'])
    response = client.get_parameter(
        Name=username,
        WithDecryption= True
    )
    response = client.put_parameter(
        Name=username,
        Description='modified by LOCK', #config desc
        Value='Key Id: '+ str(new_key[0])+' Secret Key: '+str(new_key[1]),  # Key ID: XXXXXX Secret Key: XXXX
        Type='SecureString',
        Overwrite=True
    )
    print(response)

