from azure.devops.connection import Connection
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.monitor.models import AutoscaleSettingResourcePatch
from copy import deepcopy
from msrest.authentication import BasicAuthentication
from project import values
from time import sleep

import logging

logging.getLogger("azure.keyvault.secrets").setLevel(logging.CRITICAL)
logging.getLogger("azure.mgmt.resource.resources").setLevel(logging.CRITICAL)
logging.getLogger("azure.identity").setLevel(logging.CRITICAL)
logging.getLogger("azure.common.credentials").setLevel(logging.CRITICAL)
logging.getLogger("azure.mgmt.compute").setLevel(logging.CRITICAL)
logging.getLogger("azure.core").setLevel(logging.CRITICAL)
logging.getLogger("azure").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").setLevel(logging.CRITICAL)


def revert_changes(
    username, autoscale_settings_operations, resource_group, autoscale_setting_resource
):
    if values.DryRun:
        logging.info(
            f"User {username}: Dry run enabled. No changes to be reverted in scale set {autoscale_setting_resource.name}"
        )
        return

    autoscale_settings_operations.update(
        resource_group_name=resource_group,
        autoscale_setting_name="autoscalehost",
        autoscale_setting_resource=autoscale_setting_resource,
    )


def poll_until_success(username, client, resource_group, min_instances, interval=30):
    if values.DryRun:
        logging.info(f"User {username}: Dry run enabled. Polling will be skipped")
        return

    vm_names = set()

    logging.info(
        f"User {username}: Waiting for number of instances to reach minimum value"
    )
    while len(vm_names) != min_instances:
        virtual_machines = client.virtual_machines.list(
            resource_group_name=resource_group
        )

        for vm in virtual_machines:
            vm_names.add(vm.name)

        logging.info(f"User {username}: There are currently {len(vm_names)} instances")

        if len(vm_names) != min_instances:
            logging.info(f"User {username}: Sleeping for {interval} seconds")
            sleep(interval)

    logging.info(f"User {username}: Minimum number of instances reached!")

    logging.info(
        f"User {username}: Waiting for instances to enter provisioning state 'Succeeded'"
    )
    for vm_name in vm_names:
        state = ""
        while state != "Succeeded":
            state = client.virtual_machines.get(
                resource_group_name=resource_group, vm_name=vm_name
            ).provisioning_state
            logging.debug(f"{vm_name} State: {state}")

            if state != "Succeeded":
                logging.info(f"User {username}: Sleeping for {interval} seconds")
                sleep(interval)
        logging.info(
            f"User {username}: {vm_name} is now in provisioning state 'Succeeded'"
        )


def scale_up_instances(username, autoscale_settings_operations, resource_group):
    logging.info(f"User {username}: Doubling minimum instance capacity")
    autoscale_setting = autoscale_settings_operations.get(
        resource_group_name=resource_group, autoscale_setting_name="autoscalehost"
    )

    profile = autoscale_setting.profiles[0]
    capacity = profile.capacity

    autoscale_setting_resource = AutoscaleSettingResourcePatch(
        tags=autoscale_setting.tags,
        profiles=autoscale_setting.profiles,
        notifications=autoscale_setting.notifications,
        enabled=autoscale_setting.enabled,
        name=autoscale_setting.name,
        target_resource_uri=autoscale_setting.target_resource_uri,
        target_resource_location=autoscale_setting.target_resource_location,
    )
    old_autoscale_setting_resource = deepcopy(autoscale_setting_resource)

    minimum = int(capacity.minimum)
    maximum = int(capacity.maximum)
    max_increase = maximum - minimum * 2

    if max_increase < 0:
        max_increase = 0

    for rule in profile.rules:
        if rule.scale_action.direction == "Increase":
            increase_value = int(rule.scale_action.value)
            rule.scale_action.value = (
                increase_value if increase_value < max_increase else max_increase
            )

    if values.DryRun:
        logging.info(
            f"User {username}: Dry run enabled. Instances in scale set {autoscale_setting.name} will not be cycled"
        )
        return old_autoscale_setting_resource, capacity.minimum

    if minimum * 2 <= maximum:
        capacity.minimum = minimum * 2
        capacity.default = capacity.minimum

        autoscale_settings_operations.update(
            resource_group_name=resource_group,
            autoscale_setting_name="autoscalehost",
            autoscale_setting_resource=autoscale_setting_resource,
        )

        return old_autoscale_setting_resource, capacity.minimum
    else:
        return None, None


def get_scale_sets_by_prefix(scale_set_prefix, resource_group_prefixes, scale_sets):
    matched_scale_sets = []

    for scale_set in scale_sets:
        resource_group = scale_set.id.split("/")[4].lower()
        if not any(
            [resource_group.startswith(prefix) for prefix in resource_group_prefixes]
        ):
            continue

        if scale_set_prefix in scale_set.name:
            matched_scale_sets.append(
                {"Name": scale_set.name, "ResourceGroup": resource_group}
            )

    return matched_scale_sets


def rotate_vms(config_map, username, **key_args) -> None:
    auth = config_map["Global"]["azure_credentials"][key_args.get("account")]
    credentials = ClientSecretCredential(
        auth.get("tenant"), auth.get("client_id"), auth.get("secret")
    )
    scale_set_prefix = key_args.get("scale_set_prefix")
    subscriptions = key_args.get("subscriptions")

    for subscription in subscriptions:
        logging.info(
            f"User {username}: Cycling instances under subscription {subscription['SubscriptionId']}..."
        )

        monitor_client = MonitorManagementClient(
            credential=credentials, subscription_id=subscription["SubscriptionId"]  # type: ignore
        )
        autoscale_settings_operations = monitor_client.autoscale_settings

        compute_client = ComputeManagementClient(
            credential=credentials, subscription_id=subscription["SubscriptionId"]  # type: ignore
        )
        response = compute_client.virtual_machine_scale_sets.list_all()

        resource_group_prefixes = subscription.get("ResourceGroupPrefixes")
        scale_sets = get_scale_sets_by_prefix(
            scale_set_prefix, resource_group_prefixes, response
        )

        for scale_set in scale_sets:
            old_autoscale_setting_resource, min_instances = scale_up_instances(
                username, autoscale_settings_operations, scale_set["ResourceGroup"]
            )

            if old_autoscale_setting_resource is None and min_instances is None:
                logging.info(
                    f"User {username}: No changes made to scale set {scale_set['Name']}. Skipping..."
                )
                continue

            poll_until_success(
                username, compute_client, scale_set["ResourceGroup"], min_instances
            )

            revert_changes(
                username,
                autoscale_settings_operations,
                scale_set["ResourceGroup"],
                old_autoscale_setting_resource,
            )


def set_key_vault(config_map, username, **key_args):
    key_vault_uri = key_args.get("vault_uri")
    auth = config_map["Global"]["azure_credentials"][key_args.get("account")]

    credential = ClientSecretCredential(
        auth.get("tenant"), auth.get("client_id"), auth.get("secret")
    )

    client = SecretClient(
        vault_url=key_vault_uri, credential=credential, logging_enable=False  # type: ignore
    )

    if values.DryRun is True:
        logging.info(f"User {username}: Dry run ")
    else:
        client.set_secret(
            key_args.get("key_name"),
            values.access_keys[username][0],
            logging_enable=False,
        )
        client.set_secret(
            key_args.get("key_secret"),
            values.access_keys[username][1],
            logging_enable=False,
        )
        logging.info(f"User {username}: Access key and Secret key written to key vault")
        pass


def update_pipeline_service_connection(config_map, username, **key_args):
    personal_access_token = config_map["Global"]["azure_credentials"][
        "personal_access_token"
    ]
    organization_url = key_args.get("devops_organization_url")
    projects = key_args.get("projects")

    # Create a connection to the org
    credentials = BasicAuthentication("", personal_access_token)
    connection = Connection(base_url=organization_url, creds=credentials)
    # Get a service endpoint client
    service_endpoint_client = connection.clients.get_service_endpoint_client()

    for project in projects:
        for endpoint in projects[project]:
            service_endpoints_details = (
                service_endpoint_client.get_service_endpoint_details(
                    project=project, endpoint_id=endpoint
                )
            )

            if service_endpoints_details:
                logging.info(
                    f"User {username}: Retrieved endpoint details for {service_endpoints_details.name}"
                )
                new_service_endpoint = service_endpoints_details
                if values.DryRun is True:
                    logging.info(f"User {username}: Dry run ")
                else:
                    # Update the ACCESS Key and Secret
                    new_service_endpoint.authorization.parameters["username"] = (
                        values.access_keys[username][0]
                    )
                    new_service_endpoint.authorization.parameters["password"] = (
                        values.access_keys[username][1]
                    )
                    # Now update the service endpoint
                    logging.info(
                        f"User {username}: Attempting to update credentials for {new_service_endpoint.name}"
                    )
                    service_endpoint_client.update_service_endpoint(
                        new_service_endpoint, endpoint
                    )
                    logging.info(
                        f"User {username}: Service Connection {new_service_endpoint.name} Updated"
                    )
