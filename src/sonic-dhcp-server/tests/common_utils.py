import heapq
import json
import psutil

MOCK_CONFIG_DB_PATH = "tests/test_data/mock_config_db.json"
MOCK_STATE_DB_PATH = "tests/test_data/mock_state_db.json"


class MockConfigDb(object):
    def __init__(self, config_db_path=MOCK_CONFIG_DB_PATH):
        with open(config_db_path, "r", encoding="utf8") as file:
            self.config_db = json.load(file)

    def get_config_db_table(self, table_name):
        return self.config_db.get(table_name, {})


class MockSelect(object):
    def __init__(self):
        pass

    def select(self, timeout):
        return None, None


class MockSubscribeTable(object):
    def __init__(self, tables):
        """
        Args:
            tables: table update event, sample: [
                ("Vlan1000", "SET", (("state", "enabled"),)),
                ("Vlan1000", "SET", (("customized_options", "option1"), ("state", "enabled"),))
            ]
        """
        self.stack = []
        for item in tables:
            heapq.heappush(self.stack, item)

    def pop(self):
        res = heapq.heappop(self.stack)
        return res

    def hasData(self):
        return len(self.stack) != 0


def mock_get_config_db_table(table_name):
    mock_config_db = MockConfigDb()
    return mock_config_db.get_config_db_table(table_name)


class MockProc(object):
    def __init__(self, name, pid=None, status=psutil.STATUS_RUNNING):
        self.proc_name = name
        self.pid = pid

    def name(self):
        return self.proc_name

    def send_signal(self, sig_num):
        pass

    def cmdline(self):
        if self.proc_name == "dhcrelay":
            return ["/usr/sbin/dhcrelay", "-d", "-m", "discard", "-a", "%h:%p", "%P", "--name-alias-map-file",
                    "/tmp/port-name-alias-map.txt", "-id", "Vlan1000", "-iu", "docker0", "240.127.1.2"]
        if self.proc_name == "dhcpmon":
            return ["/usr/sbin/dhcpmon", "-id", "Vlan1000", "-iu", "docker0", "-im", "eth0"]

    def terminate(self):
        pass

    def wait(self):
        pass

    def status(self):
        return self.status


class MockPopen(object):
    def __init__(self, pid):
        self.pid = pid


def mock_exit_func(status):
    raise SystemExit(status)
