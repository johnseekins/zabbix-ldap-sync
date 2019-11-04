import logging
import random
import string
import collections
import re

from pyzabbix import ZabbixAPI, ZabbixAPIException

Group = collections.namedtuple("Group", [
    "id",
    "name",
    "members",
])

# dummy ID class for groups "created" during a dry run
class FakeGroupId:
    def __eq__(self, other):
        return self is other
    def __hash__(self):
        return hash(id(self))

class User:
    def __init__(self, id, alias, groups, media, name, surname):
        self.id = id
        self.alias = alias
        self.name = name
        self.surname = surname
        self.groups = set(groups)
        self.media = media

        self.edited = False

    def set_name(self, name, surname):
        if name != self.name or surname != self.surname:
            self.name = name
            self.surname = surname
            self.edited = True

    def set_groups(self, groups):
        groups = set(groups)
        if groups != self.groups:
            self.groups = groups
            self.edited = True

    def add_group(self, groupid):
        if not groupid in self.groups:
            self.groups.add(groupid)
            self.edited = True

    def remove_group(self, groupid):
        if groupid in self.groups:
            self.groups.remove(groupid)
            self.edited = True

    def set_media(self, media_type_id, sendto, opts):
        target_entry = {
            "mediatypeid": media_type_id,
            "sendto": [sendto],
        }
        target_entry.update(opts)

        # Find an entry to update
        for media in self.media:
            if media["mediatypeid"] == media_type_id:
                # Only update if things actually changed
                if any(media[k] != v for k,v in target_entry.items()):
                    media.update(target_entry)
                    self.edited = True
                    return True
                return False
        # No entry to update, add a new one
        self.media.append(target_entry)
        self.edited = True
        return True

    def __str__(self):
        return "{} (id: {})".format(self.alias, self.id)
    def __eq__(self, other):
        return self.id == other.id
    def __hash__(self):
        return hash(self.id)

class ZabbixConn(object):
    """
    Zabbix connector class

    Defines methods for managing Zabbix users and groups

    """

    def __init__(self, config, ldap_conn):
        self.ldap_conn = ldap_conn
        self.server = config.zbx_server
        self.username = config.zbx_username
        self.password = config.zbx_password
        self.auth = config.zbx_auth
        self.dryrun = config.dryrun
        self.nocheckcertificate = config.zbx_nocheckcertificate
        self.ldap_groups = config.ldap_groups
        self.ldap_media = config.ldap_media
        self.media_opt = config.media_opt
        self.deleteorphans = config.zbx_deleteorphans
        self.media_description = config.media_description
        self.user_opt = config.user_opt
        self.disable_mode = config.ldap_disabledmode
        self.delete_mode = config.ldap_deletedmode
        self.disabled_group = config.zbx_disabled_group
        self.fake_groups = frozenset()
        if self.nocheckcertificate:
            from requests.packages.urllib3 import disable_warnings
            disable_warnings()

        if config.ldap_wildcard_search:
            self.ldap_groups = ldap_conn.get_groups_with_wildcard()

        if (self.disable_mode == "set-disabled" or self.delete_mode == "set-disabled") and not self.disabled_group:
            raise RuntimeError("`set-disabled` requires a disabled group to be set in the configuration, but nothing was supplied")

        self.logger = logging.getLogger()

    def connect(self):
        """
        Establishes a connection to the Zabbix server

        Raises:
            SystemExit

        """

        if self.auth == "webform":
            self.conn = ZabbixAPI(self.server)
        elif self.auth == "http":
            self.conn = ZabbixAPI(self.server, use_authenticate=False)
            self.conn.session.auth = (self.username, self.password)

        else:
            raise SystemExit('api auth method not implemented: %s' % self.conn.auth)

        if self.nocheckcertificate:
            self.conn.session.verify = False

        try:
            self.conn.login(self.username, self.password)
        except ZabbixAPIException as e:
            raise SystemExit('Cannot login to Zabbix server: %s' % e)

        self.logger.info("Connected to Zabbix API Version %s" % self.conn.api_version())

    def get_users(self):
        """
        Retrieves the existing Zabbix users

        Returns:
            Dict of lowercased user aliases to `User` objects

        """
        # remove some user media fields that we can't submit back
        def clean_media(entry):
            entry.pop("mediaid", None)
            entry.pop("userid", None)
            entry.pop("description", None)
            return entry
        zabbix_users = self.conn.user.get(selectMedias="extend", selectUsrgrps="extend")
        zabbix_users = {user["alias"].lower(): User(
            id=user["userid"],
            name=user["name"],
            surname=user["surname"],
            alias=user["alias"],
            groups=set(g["usrgrpid"] for g in user["usrgrps"]),
            media=[clean_media(entry) for entry in user["medias"]],
        ) for user in zabbix_users}
        return zabbix_users

    def get_mediatype_id(self, description):
        """
        Retrieves the mediatypeid by description

        Args:
            description (str): Zabbix media type description

        Returns:
            The mediatypeid for specified media type description

        """
        result = self.conn.mediatype.get(filter={'description': description})

        if result:
            mediatypeid = result[0]['mediatypeid']
        else:
            mediatypeid = None

        return mediatypeid

    def get_groups(self):
        """
        Retrieves the existing Zabbix groups

        Returns:
            A dict with group name keys and `Group` object values

        """
        result = self.conn.usergroup.get(status=0, output='extend', selectUsers="extend")
        groups = {group["name"]: Group(
            name=group["name"],
            id=group["usrgrpid"],
            members=group["users"],
        ) for group in result}
        return groups

    def create_group(self, group):
        """
        Creates a new Zabbix group

        Args:
            group (str): The Zabbix group name to create

        Returns:
            The groupid of the newly created group

        """
        if self.dryrun:
            self.logger.info("Would create group %s", group)
            return FakeGroupId()
        result = self.conn.usergroup.create(name=group)
        groupid = result['usrgrpids'][0]
        self.logger.info("Create group %s with id %s", group, groupid)
        return groupid

    def create_user(self, user, user_opt={}):
        """
        Creates a new Zabbix user

        Args:
            user     (User): User object to add
            user_opt (dict): User options
        """
        assert user.id is None
        if self.dryrun:
            self.logger.debug("Would create user %s in zabbix", user.alias)
            return

        random_passwd = ''.join(random.sample(string.ascii_letters + string.digits, 32))

        user_req = {
            'autologin': 0,
            'type': 1,
            'usrgrps': [{'usrgrpid': str(id)} for id in user.groups],
            'passwd': random_passwd,
            "alias": user.alias,
            "name": user.name,
            "surname": user.surname,
        }
        user_req.update(user_opt)

        result = self.conn.user.create(user_req)
        user.id = result["userids"][0]
        self.logger.debug("Created user %s in zabbix, id: %s", user.alias, user.id)

    def update_user(self, user):
        """
        """
        assert user.id is not None
        if not user.edited:
            self.logger.debug("User %s (id %s) unaltered", user.name, user.id)
            return

        if self.dryrun:
            self.logger.debug("Would update user %s (id %s)", user.name, user.id)
            return

        user_req = {
            "userid": user.id,
            "name": user.name,
            "surname": user.surname,
            "usrgrps": [{'usrgrpid': str(id)} for id in user.groups],
            "user_medias": user.media,
        }
        self.conn.user.update(user_req)

    def delete_user(self, user):
        """
        Deletes Zabbix user

        Args:
            user (User): User object

        """
        assert user.id is not None
        if self.dryrun:
            self.logger.info("Would delete user %s (id %s)", user.alias, user.id)
            return
        result = self.conn.user.delete(user.id)
        return result

    def convert_severity(self, severity):

        converted_severity = severity.strip()

        if re.match("\d+", converted_severity):
            return converted_severity

        sev_entries = collections.OrderedDict({
            "Disaster": "0",
            "High": "0",
            "Average": "0",
            "Warning": "0",
            "Information": "0",
            "Not Classified": "0",
        })

        for sev in converted_severity.split(","):
            sev = sev.strip()
            if sev not in sev_entries:
                raise Exception("wrong argument: %s" % sev)
            sev_entries[sev] = "1"

        str_bitmask = ""
        for sev, digit in sev_entries.items():
            str_bitmask += digit

        converted_severity = str(int(str_bitmask, 2))
        self.logger.info('Converted severity "%s" to "%s"' % (severity, converted_severity))

        return converted_severity

    def sync_users(self):
        """
        Syncs Zabbix with LDAP users
        """

        self.ldap_conn.connect()
        zabbix_users = self.get_users()
        zabbix_groups = self.get_groups()
        ldap_users = dict()
        ldap_group_members = dict()
        seen_zabbix_users = set()

        # Get the ID for the disabled group, if it exists
        if self.disabled_group:
            results = self.conn.usergroup.get(filter={"name": self.disabled_group})
            if not results:
                raise RuntimeError('Disabled group {!r} does not exist'.format(self.disabled_group))
            disabled_group_id = results[0]["usrgrpid"]

        # Parse media options
        if self.ldap_media:
            media_only_create = False
            media_opts = {
                "severity": "63",
                "active": "0",
                "period": "1-7,00:00-24:00",
            }
            media_type_id = self.conn.mediatype.get(output="extend", filter={"description": self.media_description.lower()})[0]["mediatypeid"]
            for elem in self.media_opt:
                if elem[0] == "onlycreate" and elem[1].lower() == "true":
                    media_only_create = True
                if elem[0] == "severity":
                    media_opts[elem[0]] = self.convert_severity(elem[1])
                else:
                    media_opts[elem[0]] = elem[1]

        # Go through each group we manage, create it if it doesn't exist, and get the users
        # that we manage.
        for group_name in self.ldap_groups:
            zabbix_group = zabbix_groups.get(group_name)
            if not zabbix_group:
                # Group does not exist, create it
                group_id = self.create_group(group_name)
                zabbix_group = Group(id=group_id, name=group_name, members=[])
                zabbix_groups[group_id] = zabbix_group

            # Get group members in LDAP
            members = self.ldap_conn.get_group_members(group_name)
            ldap_group_members[group_name] = members

            # Cache LDAP info
            for name, dn in members.items():
                ldap_users[name.lower()] = dn

        # Update/create users that are in ldap
        for name, dn in ldap_users.items():
            is_enabled = self.disable_mode == "ignore" or self.ldap_conn.is_user_enabled(dn)

            ldap_name = self.ldap_conn.get_user_givenName(dn) or ""
            ldap_surname = self.ldap_conn.get_user_sn(dn) or ""

            zabbix_user = zabbix_users.get(name)
            if not zabbix_user:
                if not is_enabled and self.disable_mode == "remove-groups":
                    # Don't bother creating; user won't have any groups and would just be dropped again
                    continue

                self.logger.info("Will create user %s", name)
                zabbix_user = User(
                    id=None,
                    alias=name,
                    name=ldap_name,
                    surname=ldap_surname,
                    groups=[],
                    media=[],
                )
                zabbix_users[name] = zabbix_user
            else:
                zabbix_user.set_name(ldap_name, ldap_surname)

            seen_zabbix_users.add(zabbix_user)

            # Update groups
            if not is_enabled and self.disable_mode == "set-disabled":
                # Not enabled; Replace group with the disabled group
                self.logger.info("Will move %s (id: %s, disabled in ldap) to disabled group",
                    zabbix_user.alias, zabbix_user.id)
                zabbix_user.set_groups((disabled_group_id,))
            elif not is_enabled and self.disable_mode == "remove-groups":
                # Not enabled; remove all managed groups
                for zabbix_group in zabbix_groups.values():
                    self.logger.info("Will remove user %s (id: %s, disabled in ldap) from group %s",
                        zabbix_user.alias, zabbix_user.id, zabbix_group.name)
                    zabbix_user.remove_group(zabbix_group.id)
            else:
                # Enabled, or not enabled and mode is ignore. Add+remove groups
                if self.disable_mode == "set-disabled" and disabled_group_id in zabbix_user.groups:
                    self.logger.info("Will remove user %s (id: %s) from disabled group",
                        zabbix_user.alias, zabbix_user.id)
                    zabbix_user.remove_group(disabled_group_id)

                for group_name in self.ldap_groups:
                    zabbix_group = zabbix_groups[group_name]
                    if name in ldap_group_members[group_name] and zabbix_group.id not in zabbix_user.groups:
                        self.logger.info("Will add user %s (id: %s) to group %s",
                            zabbix_user.alias, zabbix_user.id, zabbix_group.name)
                        zabbix_user.add_group(zabbix_group.id)
                    if name not in ldap_group_members[group_name] and zabbix_group.id in zabbix_user.groups:
                        self.logger.info("Will remove user %s (id: %s) from group %s",
                            zabbix_user.alias, zabbix_user.id, zabbix_group.name)
                        zabbix_user.remove_group(zabbix_group.id)

            # Update media
            if self.ldap_media and not (media_only_create and user.id is not None):
                sendto = self.ldap_conn.get_user_media(dn, self.ldap_media)
                if zabbix_user.set_media(media_type_id, sendto, media_opts):
                    self.logger.info("Will update media of user %s (id: %s)",
                        zabbix_user.alias, zabbix_user.id)

        # Handle users that are not in ldap
        if self.delete_mode != "ignore":
            non_ldap_users = set(zabbix_users.values()) - seen_zabbix_users
            for zabbix_user in non_ldap_users:
                managed = any(g.id in zabbix_user.groups for g in zabbix_groups.values())
                if not managed:
                    continue

                if self.delete_mode == "set-disabled":
                    self.logger.info("Will move %s (id: %s, not in ldap) to disabled group",
                        zabbix_user.alias, zabbix_user.id)
                    zabbix_user.set_groups((disabled_group_id,))
                elif self.delete_mode == "remove-groups":
                    self.logger.info("Will remove managed groups from %s (id: %s) (not in ldap)",
                        zabbix_user.alias, zabbix_user.id)
                    for group_name in self.ldap_groups:
                        zabbix_group = zabbix_groups[group_name]
                        self.logger.info("Will remove user %s (id: %s, not in ldap) from group %s",
                            zabbix_user.alias, zabbix_user.id, zabbix_group.name)
                        zabbix_user.remove_group(zabbix_group.id)
                else:
                    assert False

        # Write ldap changes
        self.logger.info("Writing changes to Zabbix")
        for zabbix_user in zabbix_users.values():
            if zabbix_user.id is None:
                # User didn't exist, create
                self.create_user(zabbix_user, self.user_opt)
            elif zabbix_user.groups:
                # User exists and still has groups, update.
                self.update_user(zabbix_user)
            elif self.deleteorphans:
                # User doesn't exist, delete
                self.logger.info("Deleting user %s; no groups", zabbix_user)
                self.delete_user(zabbix_user)
            else:
                self.logger.error("Not updating user %s (id %s); would have removed all groups, but zabbix requires one, and --delete-orphans wasn't specified",
                    zabbix_user.alias, zabbix_user.alias)

        # for eachGroup in self.ldap_groups:

        #     ldap_users = self.ldap_conn.get_group_members(eachGroup)
        #     # Lowercase list of users
        #     ldap_users = {k.lower(): v for k,v in ldap_users.items()}

        #     if self.disable_mode == "disable":
        #         for user, dn in ldap_users.items():
        #             if user not in ldap_users_enabled:
        #                 enabled  = self.ldap_conn.is_user_enabled(dn)
        #                 ldap_users_enabled[user] = enabled
        #                 # Users in zabbix need at least one group, so move disabled users as we see them. Otherwise
        #                 # the following code will try to strip users of all their groups.
        #                 if enabled:
        #                     self.logger.info('Ensuring "%s" is enabled', user)
        #                     if not self.dryrun:
        #                         self.set_user_groups(user, [])
        #                 else:
        #                     self.logger.info('Disabling user "%s"', user)
        #                     if not self.dryrun:
        #                         self.set_user_groups(user, [self.disabled_group_id])

        #     if eachGroup in self.fake_groups:
        #         zabbix_grpid = FAKE_ZABBIX_GROUP_ID
        #     else:
        #         zabbix_grpid = next(g['usrgrpid'] for g in self.get_groups() if g['name'] == eachGroup)

        #     zabbix_group_users = self.get_group_members(zabbix_grpid)

        #     seen_zabbix_users.update(zabbix_group_users)
        #     seen_ldap_users.update(ldap_users.keys())

        #     missing_users = set(ldap_users.keys()) - set(zabbix_group_users) - set(user for user,enabled in ldap_users_enabled.items() if not enabled)

        #     # Add missing users
        #     for eachUser in missing_users:

        #         # Create new user if it does not exists already
        #         if eachUser not in zabbix_all_users:
        #             self.logger.info('Creating user "%s", member of Zabbix group "%s"' % (eachUser, eachGroup))
        #             user = {'alias': eachUser}

        #             if self.ldap_conn.get_user_givenName(ldap_users[eachUser]) is None:
        #                 user['name'] = ''
        #             else:
        #                 user['name'] = self.ldap_conn.get_user_givenName(ldap_users[eachUser]).decode('utf8')
        #             if self.ldap_conn.get_user_sn(ldap_users[eachUser]) is None:
        #                 user['surname'] = ''
        #             else:
        #                 user['surname'] = self.ldap_conn.get_user_sn(ldap_users[eachUser]).decode('utf8')

        #             if not self.dryrun:
        #               self.create_user(user, zabbix_grpid, self.user_opt)
        #             zabbix_all_users.append(eachUser)
        #         else:
        #             # Update existing user to be member of the group
        #             self.logger.info('Updating user "%s", adding to group "%s"' % (eachUser, eachGroup))
        #             if not self.dryrun:
        #               self.edit_user_groups(eachUser, add=[zabbix_grpid])

        #     removed_users = set(zabbix_group_users) - set(ldap_users.keys())
        #     for user in removed_users:
        #         self.logger.info('Removing user "%s" from group %s', user, eachGroup)
        #         if not self.dryrun:
        #             self.edit_user_groups(user, remove=[zabbix_grpid])

        #     # update users media
        #     onlycreate = False
        #     media_opt_filtered = []
        #     for elem in self.media_opt:
        #         if elem[0] == "onlycreate" and elem[1].lower() == "true":
        #             onlycreate = True
        #         if elem[0] == "severity":
        #             media_opt_filtered.append(
        #                 (elem[0], self.convert_severity(elem[1]))
        #             )
        #         else:
        #             media_opt_filtered.append(elem)

        #     if onlycreate:
        #         media_users_set = missing_users
        #     else:
        #         media_users_set = self.get_group_members(zabbix_grpid)

        #     for user in media_users_set:
        #         if user.lower() in ldap_users:
        #             users_to_update_media_of[user] = ldap_users[user.lower()]

        # # Handle any extra users in the groups
        # extra_users = seen_zabbix_users - seen_ldap_users
        # if extra_users:
        #     for eachUser in extra_users:
        #         if self.deleteorphans:
        #             self.logger.info('Deleting user: "%s"' % eachUser)
        #             if not self.dryrun:
        #                 self.delete_user(eachUser)
        #         else:
        #             self.logger.info('User not in any ldap group "%s"' % eachUser)

        # # Update media
        # if self.ldap_media:
        #     for eachUser, ldapinfo in users_to_update_media_of.items():
        #         sendto = self.ldap_conn.get_user_media(ldapinfo, self.ldap_media)
        #         if isinstance(sendto, bytes):
        #             sendto = sendto.decode("utf-8")
        #         self.logger.info('>>> Updating/create user media for "%s", set "%s" to "%s"', eachUser, self.media_description, sendto)
        #         if sendto and not self.dryrun:
        #             self.update_media(eachUser, self.media_description, sendto, media_opt_filtered)
        # else:
        #     self.logger.info('>>> Ignoring media because of configuration')

        self.ldap_conn.disconnect()
