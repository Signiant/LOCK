import logging
import pprint
import boto3
import time
from project import values
from project.plugins.iam import get_iam_session


def get_ec2_client(configMap):
    if values.profile is not None:
        session = get_iam_session()
        return session.client('ec2')
    else:
        return boto3.client('ec2', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])


def list_instances(configMap, instances):

    client = get_ec2_client(configMap)
    intance_IDs = []

    response = client.describe_instances()
    for instance in response.get('Reservations'):
        instance = instance.get('Instances')[0]
        for name in instance.get('Tags'):
                if name.get('Key') == 'Name':
                    if name.get('Value') in instances:
                        instanceName = name.get('Value')
                        intance_IDs.append(instance.get('InstanceId'))
                        print(instanceName + " Instance ID: " + instance.get('InstanceId'))
    return intance_IDs


def terminate_instance_id(configMap, **key_args):

    client = get_ec2_client(configMap)
    response = client.terminate_instances(InstanceIds=[key_args.get('instance_id')],)
    logging.critical(key_args.get('instance_id')+ " instance terminated")

def get_instance_status(configMap, **key_args):

    client = get_ec2_client(configMap)
    response = client.describe_instances(InstanceIds=[key_args.get('instance_id')])
    pprint.pprint(response.get('Reservations')[0].get('Instances'))


def get_describe_instance_status(configMap, **key_args):

    client = get_ec2_client(configMap)
    response = client.describe_instance_status(InstanceIds=[key_args.get('instance_id')])
    return(response.get('InstanceStatuses')[0].get('InstanceStatus').get('Details')[0].get('Status'))


def terminate_instances(configMap, username,  **key_args):

    instance_names = key_args.get('instances')
    print(instance_names)

    for instance_name in instance_names:
        instances = list_instances(configMap, instance_name)
        growing_instance_list = instances  # list grows as more instances are terminated and new ones are generated
        for instanceid in instances:
            reachable = False
            key_args['instance_id'] = instanceid

            if values.DryRun is True:
                logging.info('Dry run of terminate instance:'+ instanceid)
            else:
                # terminate_instance_id(configMap, **key_args)
                while(reachable==False):
                    checkinstancelist = list_instances(configMap, instance_name)
                    if len(checkinstancelist) > len(growing_instance_list):
                        new_instance_id = list(set(checkinstancelist) - set(growing_instance_list))
                        key_args['instance_id'] = new_instance_id[0]
                        instance_reachability = get_describe_instance_status(configMap, **key_args)
                        if instance_reachability == "passed":
                            reachable = True
                            growing_instance_list = checkinstancelist
                    if not reachable:
                        time.sleep(60)

            logging.info('moving to next instance')
    pass