import json
import pprint

import boto3


def get_ec2_client(configMap):
    return boto3.client('ec2', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])

def list_instances(configMap,  **key_args):

    instances = key_args.get('instances')
    instance_name = key_args.get('instance_name')

    client=get_ec2_client(configMap)

    response = client.describe_instances()
    for instance in response.get('Reservations'):
        instance = instance.get('Instances')[0]
        #pprint.pprint(instance)
        #if instance.get('State')['Name'] == "running" :
        for name in instance.get('Tags'):
                if name.get('Key')=='Name' :
                    if name.get('Value') in instances:
                        instanceName=name.get('Value')
                        instance.get('InstanceId')
                        print(instanceName + " id: " + instance.get('InstanceId'))


def stop_instance(configMap, **key_args):

    client=get_ec2_client(configMap)
    response = client.stop_instances(InstanceIds=[key_args.get('instance_id')],)

def get_instance_status(configMap, **key_args):

    client=get_ec2_client(configMap)
    response = client.describe_instances(InstanceIds=[key_args.get('instance_id')])
    print(response)


