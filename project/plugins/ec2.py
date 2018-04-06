import logging
import pprint
import boto3
import time
from project import values
from project.plugins.iam import get_iam_session


def get_ec2_client(configMap, **key_args):
    if values.profile is not None:

        session = get_iam_e_session(**key_args)
        return session.client('ec2')
    else:
        return boto3.client('ec2', aws_access_key_id=configMap['Global']['id'],
                               aws_secret_access_key=configMap['Global']['secret'])


def get_iam_e_session(**key_args):
    return boto3.Session(profile_name=values.profile, region_name=key_args.get('region'))

def get_elb_client(configMap, **key_args):
    if values.profile is not None:
        session = get_iam_e_session(**key_args)
        return session.client('elb')
    else:
        return boto3.client('elb', aws_access_key_id=configMap['Global']['id'],
                            aws_secret_access_key=configMap['Global']['secret'])



def list_instances(configMap, instance_name,  **key_args):

    client = get_ec2_client(configMap, **key_args)
    intance_IDs = []

    response = client.describe_instances()
    for instance in response.get('Reservations'):
        instance = instance.get('Instances')[0]
        #print(instance)
        try:
            for name in instance.get('Tags'):
                    if name.get('Key') == 'Name':
                        if name.get('Value') in instance_name:
                            instanceName = name.get('Value')
                            intance_IDs.append(instance.get('InstanceId'))
                            #print(instanceName + " Instance ID: " + instance.get('InstanceId'))
        except:
            pass
    return intance_IDs


def terminate_instance_id(configMap, **key_args):

    client = get_ec2_client(configMap, **key_args)
    response = client.terminate_instances(InstanceIds=[key_args.get('instance_id')],)
    logging.critical(key_args.get('instance_id')+ " instance terminated")

def get_instance_status(configMap, **key_args):

    client = get_ec2_client(configMap, **key_args)
    response = client.describe_instances(InstanceIds=[key_args.get('instance_id')])
    pprint.pprint(response.get('Reservations')[0].get('Instances'))


def get_describe_instance_status(configMap, **key_args):

    client = get_ec2_client(configMap, **key_args)
    response = client.describe_instance_status(InstanceIds=[key_args.get('instance_id')])
    return(response.get('InstanceStatuses')[0].get('InstanceStatus').get('Details')[0].get('Status'))


def terminate_instances(configMap, username,  **key_args):

    elb_client = get_elb_client(configMap, **key_args)


    instance_names = key_args.get('instances')
    print(instance_names)

    for instance_name in instance_names:
        elb_name = get_loadbalancername(configMap, instance_name, elb_client, **key_args)
        print(elb_name)
        instances = list_instances(configMap, instance_name,  **key_args)
        growing_instance_list = instances  # list grows as more instances are terminated and new ones are generated
        for instanceid in instances:
            reachable = False
            key_args['instance_id'] = instanceid

            if values.DryRun is True:
                logging.info('Dry run instance:'+instance_name + " " + instanceid)
            else:
                terminate_instance_id(configMap, **key_args)
                while(reachable==False):
                    checkinstancelist = list_instances(configMap, instance_name, **key_args)
                    if len(checkinstancelist) > len(growing_instance_list):
                        new_instance_id = list(set(checkinstancelist) - set(growing_instance_list))

                        key_args['instance_id'] = new_instance_id[0]
                        print(new_instance_id[0])
                        print(growing_instance_list)
                        instance_reachability = get_describe_instance_status(configMap, **key_args)
                        if instance_reachability == "passed":
                            reachable = True
                            growing_instance_list = checkinstancelist
                            #check load balancer
                            # logging.info('waiting 200 seconds for app to start...')
                            while not _is_instance_inService(elb_client,elb_name, new_instance_id[0]):
                                logging.info('Waiting for instance to be InService...')
                                time.sleep(45)
                    if not reachable:
                        logging.info('waiting on valid status...')
                        time.sleep(45)
    pass

def get_loadbalancername(configMap,instance_name,client, **key_args):

    response = client.describe_load_balancers()

    list_loadbalancers = response.get('LoadBalancerDescriptions')
    for loadbalancer in list_loadbalancers:
        # loadbalancer_names.append(loadbalancer.get('LoadBalancerName'))
        balancer_tags = client.describe_tags(LoadBalancerNames=[loadbalancer.get('LoadBalancerName')])
        tags = balancer_tags.get('TagDescriptions')[0].get('Tags')
        for tag in tags:
            if tag.get('Value') == instance_name:
                return loadbalancer.get('LoadBalancerName')


##
def _is_instance_inService(elb_client,elb_name, instance_id):
    response = elb_client.describe_instance_health(
                        LoadBalancerName=elb_name,
                        Instances=[
                            {
                                'InstanceId': instance_id
                            },
                        ]
                    )
    return response.get('InstanceStates')[0].get('State') =='InService'


