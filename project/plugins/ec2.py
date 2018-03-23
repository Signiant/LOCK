import json
import logging
import pprint

import boto3
from os import wait

import time


def get_ec2_client(configMap):
    return boto3.client('ec2', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])


def list_instances(configMap,  instances):

    client = get_ec2_client(configMap)
    intance_IDs = []

    response = client.describe_instances()
    for instance in response.get('Reservations'):
        instance = instance.get('Instances')[0]
        # if instance.get('State')['Name'] == "running" :
        for name in instance.get('Tags'):
                if name.get('Key') == 'Name':
                    if name.get('Value') in instances:
                        instanceName = name.get('Value')
                        intance_IDs.append(instance.get('InstanceId'))
                        print(instanceName + " Instance ID: " + instance.get('InstanceId'))
    return intance_IDs


def terminate_instance(configMap, **key_args):

    client = get_ec2_client(configMap)
    response = client.terminate_instances(InstanceIds=[key_args.get('instance_id')],)
    logging.critical(key_args.get('instance_id')+ " instance terminated")

def get_instance_status(configMap, **key_args):

    client = get_ec2_client(configMap)
    response = client.describe_instances(InstanceIds=[key_args.get('instance_id')])
    pprint.pprint(response.get('Reservations')[0].get('Instances'))


def automate_all(configMap, username,  **key_args):

    instance_names = key_args.get('instances')
    print(instance_names)

    for instance_name in instance_names:
        instances = list_instances(configMap, instance_name)
        for instanceid in instances:
            key_args['instance_id'] = instanceid
            # terminate_instance(configMap, **key_args)
            checkinstancelist = list_instances(configMap, instance_name)

            while(len(checkinstancelist) <= len(instances)):
                checkinstancelist = list_instances(configMap, instance_name)
                time.sleep(120)
            print('moving to next instance')
    pass