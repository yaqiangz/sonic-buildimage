import ipaddress
import sys
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


class ConfigDbEventChecker(object):
    table_name = ""
    subscriber_state_table = None
    enabled = False

    def __init__(self, sel):
        """
        Init function
        Args:
            sel: select object to manage subscribe table
            db_connector: db connector
        """
        self.sel = sel

    @classmethod
    def get_all_subclasses(cls):
        """
        Function to get all subclasses
        """
        return cls.__subclasses__() + [g for s in cls.__subclasses__() for g in s.get_all_subclasses()]

    @classmethod
    def get_parameter_by_name(cls, db_snapshot, param_name):
        """
        Check whether db_snapshot valid
        Args:
            db_snapshot: dict contains db_snapshot param
            param_name: parameter name need to check
        Returns:
            If param_name in db_snapshot return tuple of (True, parameter), else return tuple of (False, None)
        """
        if param_name not in db_snapshot:
            return False, None
        return True, db_snapshot[param_name]

    def is_enabled(self):
        """
        Check whether checker is enabled
        Returns:
            If enabled, return True. Else return False
        """
        return self.enabled

    def enable(self, db):
        """
        Enable checker by subscribe table
        Args:
            db: db object
        """
        if self.enabled:
            syslog.syslog(syslog.LOG_ERR, "Cannot enable {} checker due to it is enabled"
                          .format(self.table_name))
            sys.exit(1)
        self.subscriber_state_table = swsscommon.SubscriberStateTable(db, self.table_name)
        self.sel.addSelectable(self.subscriber_state_table)
        self.enabled = True

    def disable(self):
        """
        Disable checker
        """
        if not self.enabled:
            syslog.syslog(syslog.LOG_ERR, "Cannot disable {} checker due to it is disabled"
                          .format(self.table_name))
            sys.exit(1)
        self.sel.removeSelectable(self.subscriber_state_table)
        self.enabled = False

    def _clear_event(self):
        """
        Clear update event of subscirbe table
        """
        if not self.enabled:
            syslog.syslog(syslog.LOG_ERR, "Cannot clear event for table {} due to it is disabled"
                          .format(self.table_name))
            sys.exit(1)
        while self.subscriber_state_table.hasData():
            _, _, _ = self.subscriber_state_table.pop()

    @abstractmethod
    def _get_parameter(self, db_snapshot):
        """
        Get paramter depends on subclass
        Args:
            db_snapshot: dict of db snapshot
        """
        raise NotImplementedError

    @abstractmethod
    def _process_check(self, key, op, entry, parameter):
        """
        Check whether this event contains value we interested
        Args:
            key: key of event
            op: operation of event
            entry: operation entry of event
            paramter: parameter used in check
        Returns:
            If contains, return True, else return False
        """
        raise NotImplementedError

    def check_update_event(self, db_snapshot):
        """
        Function to check whether interested field changed in subscribe table
        Args:
            db_snapshot: dict contains db_snapshot param
        Returns:
            If changed, return True, else return False
        """
        res, parameter = self._get_parameter(db_snapshot)
        if not res:
            return True
        need_refresh = False
        while self.subscriber_state_table.hasData():
            key, op, entry = self.subscriber_state_table.pop()
            need_refresh |= self._process_check(key, op, entry, parameter)
            if need_refresh:
                self._clear_event()
                return True
        return False

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
            syslog.syslog(syslog.LOG_ERR, "Expected param: {} is not in db_snapshot".format(param_name))
            return False

        return True


class DhcpServerTableCfgChangeEventChecker(ConfigDbEventChecker):
    """
    This event checker interested in all DHCP server related config change event in DHCP_SERVER_IPV4 table
    """
    def __init__(self, sel):
        self.table_name = DHCP_SERVER_IPV4
        ConfigDbEventChecker.__init__(self, sel)

    def _get_parameter(self, db_snapshot):
        return ConfigDbEventChecker.get_parameter_by_name(db_snapshot, "enabled_dhcp_interfaces")

    def _process_check(self, key, op, entry, enabled_dhcp_interfaces):
        # If old state is enabled, need refresh
        if key in enabled_dhcp_interfaces:
            return True
        elif op == "SET":
            for field, value in entry:
                if field != "state":
                    continue
                # If old state is not consistent with new state, need refresh
                if value == "enabled":
                    return True
        return False


class DhcpServerTableIntfEnablementEventChecker(ConfigDbEventChecker):
    """
    This event checker only interested in DHCP interface enabled/disabled in DHCP_SERVER_IPV4 table
    """
    def __init__(self, sel):
        self.table_name = DHCP_SERVER_IPV4
        ConfigDbEventChecker.__init__(self, sel)

    def _get_parameter(self, db_snapshot):
        return ConfigDbEventChecker.get_parameter_by_name(db_snapshot, "enabled_dhcp_interfaces")

    def _process_check(self, key, op, entry, enabled_dhcp_interfaces):
        if op == "SET":
            for field, value in entry:
                if field != "state":
                    continue
                # Only if new state is not consistent with old state, we need to refresh
                if key in enabled_dhcp_interfaces and value == "disabled":
                    return True
                elif key not in enabled_dhcp_interfaces and value == "enabled":
                    return True
        # For del operation, we can skip disabled change
        if op == "DEL":
            if key in enabled_dhcp_interfaces:
                return True
        return False


class DhcpPortTableEventChecker(ConfigDbEventChecker):
    """
    This event checker interested in changes in DHCP_SERVER_IPV4_PORT table
    """
    def __init__(self, sel):
        self.table_name = DHCP_SERVER_IPV4_PORT
        ConfigDbEventChecker.__init__(self, sel)

    def _get_parameter(self, db_snapshot):
        return ConfigDbEventChecker.get_parameter_by_name(db_snapshot, "enabled_dhcp_interfaces")

    def _process_check(self, key, op, entry, enabled_dhcp_interfaces):
        dhcp_interface = key.split("|")[0]
        # If dhcp interface is enabled, need to generate new configuration
        if dhcp_interface in enabled_dhcp_interfaces:
            self._clear_event()
            return True
        return False


class DhcpRangeTableEventChecker(ConfigDbEventChecker):
    """
    This event checker interested in changes in DHCP_SERVER_IPV4_RANGE table
    """
    def __init__(self, sel):
        self.table_name = DHCP_SERVER_IPV4_RANGE
        ConfigDbEventChecker.__init__(self, sel)

    def _get_parameter(self, db_snapshot):
        return ConfigDbEventChecker.get_parameter_by_name(db_snapshot, "used_range")

    def _process_check(self, key, op, entry, used_range):
        # If range is used, need to generate new configuration
        if key in used_range:
            self._clear_event()
            return True
        return False


class DhcpOptionTableEventChecker(ConfigDbEventChecker):
    """
    This event checker interested in changes in DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS table
    """
    def __init__(self, sel):
        self.table_name = DHCP_SERVER_IPV4_CUSTOMIZED_OPTIONS
        ConfigDbEventChecker.__init__(self, sel)

    def _get_parameter(self, db_snapshot):
        return ConfigDbEventChecker.get_parameter_by_name(db_snapshot, "used_options")

    def _process_check(self, key, op, entry, used_options):
        # If option is used, need to generate new configuration
        if key in used_options:
            self._clear_event()
            return True
        return False


class VlanTableEventChecker(ConfigDbEventChecker):
    """
    This event checker interested in changes in VLAN table
    """
    def __init__(self, sel):
        self.table_name = VLAN
        ConfigDbEventChecker.__init__(self, sel)

    def _get_parameter(self, db_snapshot):
        return ConfigDbEventChecker.get_parameter_by_name(db_snapshot, "enabled_dhcp_interfaces")

    def _process_check(self, key, op, entry, enabled_dhcp_interfaces):
        # For vlan doesn't have related dhcp entry, not need to refresh dhcrelay process
        if key in enabled_dhcp_interfaces:
            self._clear_event()
            return True
        return False


class VlanIntfTableEventChecker(ConfigDbEventChecker):
    """
    This event checker interested in changes in VLAN_INTERFACE table
    """
    def __init__(self, sel):
        self.table_name = VLAN_INTERFACE
        ConfigDbEventChecker.__init__(self, sel)

    def _get_parameter(self, db_snapshot):
        return ConfigDbEventChecker.get_parameter_by_name(db_snapshot, "enabled_dhcp_interfaces")

    def _process_check(self, key, op, entry, enabled_dhcp_interfaces):
        splits = key.split("|")
        vlan_name = splits[0]
        ip_address = splits[1].split("/")[0] if len(splits) > 1 else None
        # For vlan doesn't have related dhcp entry, not need to refresh dhcrelay process
        if vlan_name in enabled_dhcp_interfaces and ip_address is not None and \
           ipaddress.ip_address(ip_address).version == 4:
            self._clear_event()
            return True
        return False


class VlanMemberTableEventChecker(ConfigDbEventChecker):
    """
    This event checker interested in changes in VLAN_MEMBER table
    """
    def __init__(self, sel):
        self.table_name = VLAN_MEMBER
        ConfigDbEventChecker.__init__(self, sel)

    def _get_parameter(self, db_snapshot):
        return ConfigDbEventChecker.get_parameter_by_name(db_snapshot, "enabled_dhcp_interfaces")

    def _process_check(self, key, op, entry, enabled_dhcp_interfaces):
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
        self.checker_dict[DHCP_SERVER_IPV4] = DhcpServerTableIntfEnablementEventChecker(self.sel)
        self.checker_dict[VLAN] = VlanTableEventChecker(self.sel)
        self.checker_dict[VLAN_INTERFACE] = VlanIntfTableEventChecker(self.sel)

    def enable_checker(self, checker_names):
        """
        Enable checkers
        Args:
            checker_names: set of tables checker to be enable
        """
        for table in checker_names:
            if table not in self.checker_dict:
                syslog.syslog(syslog.LOG_ERR, "Cannot find checker for {} in checker_dict".format(table))
                continue
            self.checker_dict[table].enable(self.db_connector.config_db)

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
        return (self.checker_dict[DHCP_SERVER_IPV4].check_update_event(db_snapshot),
                self.checker_dict[VLAN].check_update_event(db_snapshot),
                self.checker_dict[VLAN_INTERFACE].check_update_event(db_snapshot))


class DhcpServdDbMonitor(object):
    checker_dict = {}

    def __init__(self, db_connector, select_timeout=DEFAULT_SELECT_TIMEOUT):
        self.db_connector = db_connector
        self.sel = swsscommon.Select()
        self.select_timeout = select_timeout
        all_checker_classes = ConfigDbEventChecker.get_all_subclasses()
        checker_list = [checker(self.sel) for checker in all_checker_classes
                        if checker != DhcpServerTableIntfEnablementEventChecker]
        for checker in checker_list:
            self.checker_dict[checker.table_name] = checker

    def disable_checkers(self, checker_names):
        """
        Disable checkers
        Args:
            checker_names: set contains name of tables need to be disable
        """
        for table in checker_names:
            if table not in self.checker_dict:
                syslog.syslog(syslog.LOG_ERR, "Cannot find checker for {} in checker_dict".format(table))
                continue
            self.checker_dict[table].disable()

    def enable_checkers(self, checker_names):
        """
        Enable checkers
        Args:
            checker_names: set contains name of tables need to be enable
        """
        for table in checker_names:
            if table not in self.checker_dict:
                syslog.syslog(syslog.LOG_ERR, "Cannot find checker for {} in checker_dict".format(table))
                continue
            self.checker_dict[table].enable(self.db_connector.config_db)

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
            if not checker.is_enabled():
                continue
            need_refresh |= checker.check_update_event(db_snapshot)
        return need_refresh
