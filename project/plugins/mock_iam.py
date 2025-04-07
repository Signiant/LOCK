import logging
from project import values

logging.getLogger("botocore").setLevel(logging.CRITICAL)


def get_new_key(_, username, **__):
    if (
        values.access_keys[username] == ("", "") and values.DryRun is False
    ):  # run only if user hasn't manually entered a key
        from project.main import update_access_key

        new_key = ("THISISAFAKEKEYXXXXXX", "this//I3afakeSecREtKeyXxXxXx45fg")
        update_access_key(username, new_key)
        if values.hide_key is True:
            print("                           New AccessKey: " + str(new_key[0]))
        else:
            print("                           New AccessKey: " + str(new_key))
        return new_key
    else:
        logging.info(f"User {username}: Dry run of get new key")
