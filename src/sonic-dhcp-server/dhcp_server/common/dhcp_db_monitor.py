import ipaddress
import syslog
from abc import abstractmethod
from swsscommon import swsscommon

DEFAULT_SELECT_TIMEOUT = 5000  # millisecond
DHCP_SERVER_IPV4 = "DHCP_SERVER_IPV4"
DHCP_SERVER_IPV4_PORT = "DHCP_SERVER_IPV4_PORT"
DHCP_SERVER_IPV4_RANGE = "DHCP_SERVER_IPV4_RANGE"
DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS = "DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS"
VLAN = "VLAN"
VLAN_MEMBER = "VLAN_MEMBER"
VLAN_INTERFACE = "VLAN_INTERFACE"


class DbEventChecker(object):
    table_name = ""
    subscribe_table = None

    def __init__(self, sel, db_connector):
        """
        Init function
        Args:
            sel: select object to manage subscribe table
            db_connector: db connector
        """
        self.sel = sel
        self.db_connector = db_connector
        self._subscribe_table(self.db_connector.config_db)

    def _subscribe_table(self, db):
        """
        Subscribe table
        """
        self.subscribe_table = swsscommon.SubscriberStateTable(db, self.table_name)
        self.sel.addSelectable(self.subscribe_table)

    def remove_subscribe(self):
        """
        Unsubscribe table
        """
        self.sel.removeSelectable(self.subscribe_table)

    def _clear_event(self):
        """
        Clear update event of subscirbe table
        """
        while self.subscribe_table.hasData():
            _, _, _ = self.subscribe_table.pop()

    def _check_db_snapshot(self, db_snapshot, param_name):
        """
        Check whether db_snapshot valid
        Args:
            db_snapshot: dict contains db_snapshot param
            param_name: parameter name need to check
        Returns:
            If param_name in db_snapshot return True, else return False
        """
        if param_name not in db_snapshot:
            syslog.syslog(syslog.LOG_ERR, "Expected param: {} is no in db_snapshot".format(param_name))
            return False

        return True

    @abstractmethod
    def check_update_event(self):
        """
        Function to check whether interested field changed in subscribe table
        """
        pass


class DhcpServerTableCfgChangeEventChecker(DbEventChecker):
    """
    This event checker interested in all DHCP server related config change event in DHCP_SERVER_IPV4 table
    """
    def __init__(self, sel, db_connector):
        self.table_name = DHCP_SERVER_IPV4
        DbEventChecker.__init__(self, sel, db_connector)

    def check_update_event(self, db_snapshot):
        if not self._check_db_snapshot(db_snapshot, "enabled_dhcp_interfaces"):
            self._clear_event()
            return True

        enabled_dhcp_interfaces = db_snapshot["enabled_dhcp_interfaces"]
        need_refresh = False
        while self.subscribe_table.hasData():
            key, op, entry = self.subscribe_table.pop()
            # If old state is enabled, need refresh
            if key in enabled_dhcp_interfaces:
                need_refresh = True
            elif op == "SET":
                for field, value in entry:
                    if field != "state":
                        continue
                    # If old state is not consistent with new state, need refresh
                    if value == "enabled":
                        need_refresh = True
            if need_refresh:
                self._clear_event()
                return True

        return False


class DhcpServerTableIntfEnablementEventChecker(DbEventChecker):
    """
    This event checker only interested in DHCP interface enabled/disabled in DHCP_SERVER_IPV4 table
    """
    def __init__(self, sel, db_connector):
        self.table_name = DHCP_SERVER_IPV4
        DbEventChecker.__init__(self, sel, db_connector)

    def check_update_event(self, db_snapshot):
        if not self._check_db_snapshot(db_snapshot, "enabled_dhcp_interfaces"):
            self._clear_event()
            return True

        enabled_dhcp_interfaces = db_snapshot["enabled_dhcp_interfaces"]
        need_refresh = False
        while self.subscribe_table.hasData():
            key, op, entry = self.subscribe_table.pop()
            if op == "SET":
                for field, value in entry:
                    if field != "state":
                        continue
                    # Only if new state is not consistent with old state, we need to refresh
                    if key in enabled_dhcp_interfaces and value == "disabled":
                        need_refresh = True
                    elif key not in enabled_dhcp_interfaces and value == "enabled":
                        need_refresh = True
            # For del operation, we can skip disabled change
            if op == "DEL":
                if key in enabled_dhcp_interfaces:
                    need_refresh = True
            if need_refresh:
                self._clear_event()
                return True
        return False


class DhcpPortTableEventChecker(DbEventChecker):
    """
    This event checker interested in changes in DHCP_SERVER_IPV4_PORT table
    """
    def __init__(self, sel, db_connector):
        self.table_name = DHCP_SERVER_IPV4_PORT
        DbEventChecker.__init__(self, sel, db_connector)

    def check_update_event(self, db_snapshot):
        if not self._check_db_snapshot(db_snapshot, "enabled_dhcp_interfaces"):
            self._clear_event()
            return True

        enabled_dhcp_interfaces = db_snapshot["enabled_dhcp_interfaces"]
        while self.subscribe_table.hasData():
            key, _, _ = self.subscribe_table.pop()
            dhcp_interface = key.split("|")[0]
            # If dhcp interface is enabled, need to generate new configuration
            if dhcp_interface in enabled_dhcp_interfaces:
                self._clear_event()
                return True
        return False


class DhcpRangeTableEventChecker(DbEventChecker):
    """
    This event checker interested in changes in DHCP_SERVER_IPV4_RANGE table
    """
    def __init__(self, sel, db_connector):
        self.table_name = DHCP_SERVER_IPV4_RANGE
        DbEventChecker.__init__(self, sel, db_connector)

    def check_update_event(self, db_snapshot):
        if not self._check_db_snapshot(db_snapshot, "used_range"):
            self._clear_event()
            return True

        used_range = db_snapshot["used_range"]
        while self.subscribe_table.hasData():
            key, _, _ = self.subscribe_table.pop()
            # If range is used, need to generate new configuration
            if key in used_range:
                self._clear_event()
                return True
        return False


class DhcpOptionTableEventChecker(DbEventChecker):
    """
    This event checker interested in changes in DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS table
    """
    def __init__(self, sel, db_connector):
        self.table_name = DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS
        DbEventChecker.__init__(self, sel, db_connector)

    def check_update_event(self, db_snapshot):
        if not self._check_db_snapshot(db_snapshot, "used_options"):
            self._clear_event()
            return True

        used_options = db_snapshot["used_options"]
        while self.subscribe_table.hasData():
            key, _, _ = self.subscribe_table.pop()
            # If range is used, need to generate new configuration
            if key in used_options:
                self._clear_event()
                return True
        return False


class VlanTableEventChecker(DbEventChecker):
    """
    This event checker interested in changes in VLAN table
    """
    def __init__(self, sel, db_connector):
        self.table_name = VLAN
        DbEventChecker.__init__(self, sel, db_connector)

    def check_update_event(self, db_snapshot):
        if not self._check_db_snapshot(db_snapshot, "enabled_dhcp_interfaces"):
            self._clear_event()
            return True

        enabled_dhcp_interfaces = db_snapshot["enabled_dhcp_interfaces"]
        while self.subscribe_table.hasData():
            key, _, _ = self.subscribe_table.pop()
            # For vlan doesn't have related dhcp entry, not need to refresh dhcrelay process
            if key not in enabled_dhcp_interfaces:
                continue
            self._clear_event()
            return True
        return False


class VlanIntfTableEventChecker(DbEventChecker):
    """
    This event checker interested in changes in VLAN_INTERFACE table
    """
    def __init__(self, sel, db_connector):
        self.table_name = VLAN_INTERFACE
        DbEventChecker.__init__(self, sel, db_connector)

    def check_update_event(self, db_snapshot):
        if not self._check_db_snapshot(db_snapshot, "enabled_dhcp_interfaces"):
            self._clear_event()
            return True

        enabled_dhcp_interfaces = db_snapshot["enabled_dhcp_interfaces"]
        while self.subscribe_table.hasData():
            key, _, _ = self.subscribe_table.pop()
            splits = key.split("|")
            vlan_name = splits[0]
            ip_address = splits[1].split("/")[0] if len(splits) > 1 else None
            # For vlan doesn't have related dhcp entry, not need to refresh dhcrelay process
            if vlan_name not in enabled_dhcp_interfaces:
                continue
            if ip_address is None or ipaddress.ip_address(ip_address).version != 4:
                continue
            self._clear_event()
            return True
        return False


class VlanMemberTableEventChecker(DbEventChecker):
    """
    This event checker interested in changes in VLAN_MEMBER table
    """
    def __init__(self, sel, db_connector):
        self.table_name = VLAN_MEMBER
        DbEventChecker.__init__(self, sel, db_connector)

    def check_update_event(self, db_snapshot):
        if not self._check_db_snapshot(db_snapshot, "enabled_dhcp_interfaces"):
            self._clear_event()
            return True

        enabled_dhcp_interfaces = db_snapshot["enabled_dhcp_interfaces"]
        while self.subscribe_table.hasData():
            key, _, _ = self.subscribe_table.pop()
            dhcp_interface = key.split("|")[0]
            # If dhcp interface is enabled, need to generate new configuration
            if dhcp_interface in enabled_dhcp_interfaces:
                self._clear_event()
                return True
        return False


class DhcpRelaydDbMonitor(object):
    def __init__(self, db_connector, select_timeout=DEFAULT_SELECT_TIMEOUT):
        self.db_connector = db_connector
        self.sel = swsscommon.Select()
        self.select_timeout = select_timeout
        self.checker_dict = {}
        self.checker_dict["dhcp_server"] = DhcpServerTableIntfEnablementEventChecker(self.sel, db_connector)
        self.checker_dict["vlan"] = VlanTableEventChecker(self.sel, db_connector)
        self.checker_dict["vlan_intf"] = VlanIntfTableEventChecker(self.sel, db_connector)

    def check_db_update(self, db_snapshot):
        """
        Fetch db and check update
        Args:
            db_snapshot: dict contains db snapshot parameter
        Returns:
            Tuple of dhcp_server table result, vlan table result, vlan_intf table result
        """
        state, _ = self.sel.select(self.select_timeout)
        if state == swsscommon.Select.TIMEOUT or state != swsscommon.Select.OBJECT:
            return (False, False, False)
        return (self.checker_dict["dhcp_server"].check_update_event(db_snapshot),
                self.checker_dict["vlan"].check_update_event(db_snapshot),
                self.checker_dict["vlan_intf"].check_update_event(db_snapshot))


class DhcpServdDbMonitor(object):
    checker_dict = {}

    def __init__(self, db_connector, subscribe_tables, select_timeout=DEFAULT_SELECT_TIMEOUT):
        self.db_connector = db_connector
        self.sel = swsscommon.Select()
        self.select_timeout = select_timeout
        self.subscribe_tables(subscribe_tables)

    def unsubscribe_tables(self, unsubscribe_tables):
        """
        Unsubscribe monitor table change of tables
        Args:
            unsubscribe_tables: set contains name of tables need to be unsubscribed
        """
        if DHCP_SERVER_IPV4 in unsubscribe_tables:
            self._unsubscribe_table("dhcp_server")
        if DHCP_SERVER_IPV4_PORT in unsubscribe_tables:
            self._unsubscribe_table("dhcp_port")
        if DHCP_SERVER_IPV4_RANGE in unsubscribe_tables:
            self._unsubscribe_table("dhcp_range")
        if DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS in unsubscribe_tables:
            self._unsubscribe_table("dhcp_option")
        if VLAN in unsubscribe_tables:
            self._unsubscribe_table("vlan")
        if VLAN_MEMBER in unsubscribe_tables:
            self._unsubscribe_table("vlan_member")
        if VLAN_INTERFACE in unsubscribe_tables:
            self._unsubscribe_table("vlan_intf")

    def subscribe_tables(self, subscribe_tables):
        """
        Subscribe monitor table change of tables
        Args:
            subscribe_tables: set contains name of tables need to be subscribed
        """
        if DHCP_SERVER_IPV4 in subscribe_tables and "dhcp_server" not in self.checker_dict:
            self.checker_dict["dhcp_server"] = DhcpServerTableCfgChangeEventChecker(self.sel, self.db_connector)
        if DHCP_SERVER_IPV4_PORT in subscribe_tables and "dhcp_port" not in self.checker_dict:
            self.checker_dict["dhcp_port"] = DhcpPortTableEventChecker(self.sel, self.db_connector)
        if DHCP_SERVER_IPV4_RANGE in subscribe_tables and "dhcp_range" not in self.checker_dict:
            self.checker_dict["dhcp_range"] = DhcpRangeTableEventChecker(self.sel, self.db_connector)
        if DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS in subscribe_tables and "dhcp_option" not in self.checker_dict:
            self.checker_dict["dhcp_option"] = DhcpOptionTableEventChecker(self.sel, self.db_connector)
        if VLAN in subscribe_tables and "vlan" not in self.checker_dict:
            self.checker_dict["vlan"] = VlanTableEventChecker(self.sel, self.db_connector)
        if VLAN_MEMBER in subscribe_tables and "vlan_member" not in self.checker_dict:
            self.checker_dict["vlan_member"] = VlanMemberTableEventChecker(self.sel, self.db_connector)
        if VLAN_INTERFACE in subscribe_tables and "vlan_intf" not in self.checker_dict:
            self.checker_dict["vlan_intf"] = VlanIntfTableEventChecker(self.sel, self.db_connector)

    def check_db_update(self, db_snapshot):
        """
        Fetch db and check update
        Args:
            db_snapshot: dict contains db snapshot parameter
        Returns:
            Whether need to refresh config file for kea-dhcp-server
        """
        state, _ = self.sel.select(self.select_timeout)
        if state == swsscommon.Select.TIMEOUT or state != swsscommon.Select.OBJECT:
            return False
        need_refresh = False
        for checker in self.checker_dict.values():
            need_refresh |= checker.check_update_event(db_snapshot)
        return need_refresh

    def _unsubscribe_table(self, table):
        """
        Unsubscribe table monitor
        Args:
            table: name of table need to be unsubscribed
        """
        if table not in self.checker_dict:
            return
        self.checker_dict[table].remove_subscribe()
        del self.checker_dict[table]
