import pytest
from unittest.mock import patch
import dhcpservd.dhcp_server_utils as dhcp_server_utils


@pytest.fixture
def mock_swsscommon_dbconnector_init():
    with patch.object(dhcp_server_utils.swsscommon.DBConnector, "__init__", return_value=None) as mock_dbconnector_init:
        yield mock_dbconnector_init


@pytest.fixture
def mock_swsscommon_table_init():
    with patch.object(dhcp_server_utils.swsscommon.Table, "__init__", return_value=None) as mock_table_init:
        yield mock_table_init
