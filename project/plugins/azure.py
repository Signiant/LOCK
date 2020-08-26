import logging
from azure.keyvault.secrets import SecretClient
from azure.mgmt.resource import ResourceManagementClient
from azure.identity import ClientSecretCredential
from azure.common.credentials import ServicePrincipalCredentials
from project.plugins.ssh import ssh_server_command

logging.getLogger('azure.keyvault.secrets').setLevel(logging.CRITICAL)
logging.getLogger('azure.mgmt.resource').setLevel(logging.CRITICAL)
logging.getLogger('azure.identity').setLevel(logging.CRITICAL)
logging.getLogger('azure.common.credentials').setLevel(logging.CRITICAL)


def rotate_autoscalers_cloud(configMap, username,  **key_args):

    auth = configMap['Global']['azure_credentials'][key_args.get('account')]
    credentials = ServicePrincipalCredentials(tenant=auth.get('tenant'),
                                              client_id=auth.get('client_id'),
                                              secret=auth.get('secret'))
    subscriptions = key_args.get('resource_group_subscriptionid')

    for item in subscriptions:
        to_rotate = []
        for key in item:
            region = key
            for resource_group in item.get(region):
                resource_group_name = resource_group
                sub_id = item.get(region).get(resource_group)
                client = ResourceManagementClient(credentials, sub_id)
                resource_groups = client.resources.list_by_resource_group(resource_group_name)
                for rg in resource_groups:
                    if rg.type == 'Microsoft.Compute/virtualMachines':
                        to_rotate.append(rg.name)

        #Build dns names
        for vm in to_rotate: # rotate key for server type
            markers = []
            commands = []
            if 'autoscaler' in vm:
                for host in key_args.get('autoscalers'):
                    r=region.replace('-', '')
                    if r in host:
                        key_args['hostname']=host
                logging.info('      Writing key to '+key_args['hostname'])
                for pkey in key_args.get('pkeys'):
                    if region.replace('-','') in pkey:
                        key_args['pkey'] = pkey

                for marker in key_args.get('autoscaler_markers_commands'):
                    markers.append(marker)
                    commands.append(key_args.get('autoscaler_markers_commands').get(marker))
                key_args['commands'] = commands
                key_args['markers'] = markers
                ssh_server_command(configMap, username, **key_args)
            else: # its a flight server
                key_args['hostname'] = key_args.get('f_host').replace('<SERVER>', vm).replace('<REGION>', region.replace('-', ''))
                logging.info('      Writing key to '+key_args['hostname'])
                for pkey in key_args.get('pkeys'):
                    if region.replace('-', '') in pkey:
                        key_args['pkey'] = pkey
                for marker in key_args.get('fadmin_markers_commands'):
                    markers.append(marker)
                    commands.append(key_args.get('fadmin_markers_commands').get(marker))
                key_args['commands'] = commands
                key_args['markers'] = markers
                ssh_server_command(configMap, username, **key_args)


def set_key_vault(configMap, username,  **key_args):

    key_vault_uri = key_args.get('vault_uri')
    auth = configMap['Global']['azure_credentials'][key_args.get('account')]

    credential = ClientSecretCredential(auth.get('tenant'), auth.get('client_id'), auth.get('secret'))

    client = SecretClient(vault_url=key_vault_uri, credential=credential)

    from project import values
    if values.DryRun is True:
        logging.info('Dry run ')
    else:
        client.set_secret(key_args.get('key_name'), values.access_key[0])
        client.set_secret(key_args.get('key_secret'), values.access_key[1])
        logging.info("      Access key and Secret key written to key vault")
        pass
