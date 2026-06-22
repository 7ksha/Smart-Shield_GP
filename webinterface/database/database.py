from typing import (
    Dict,
    Optional,
)
import os

from smartshield_files.common.parsers.config_parser import ConfigParser
from smartshield_files.core.database.database_manager import DBManager
from smartshield_files.core.output import Output
from .signals import message_sent
from webinterface.utils import (
    get_open_redis_ports_in_order,
    get_open_redis_servers,
)


class Database(object):
    """
    connects to the latest opened redis server on init
    """

    def __init__(self):
        # get the latest port from running_smartshield_info.txt
        latest = get_open_redis_ports_in_order()
        if latest:
            port = int(latest[-1]['redis_port'])
        else:
            port = None
        self.db: DBManager = self.get_db_manager_obj(port)
        self.current_port = port

    def set_db(self, port):
        """changes the redis db we're connected to"""
        self.db = self.get_db_manager_obj(port)
        if self.db:
            self.current_port = port

    def get_db_manager_obj(self, port: int = None) -> Optional[DBManager]:
        """
        Connects to redis db through the DBManager
        connects to the latest opened redis server if no port is given
        """
        if port is None:
            # connect to the last opened port if no port is chosen by the user
            last_opened_port = get_open_redis_ports_in_order()[-1][
                "redis_port"
            ]
            port = last_opened_port

        dbs: Dict[int, dict] = get_open_redis_servers()
        output_dir = dbs[str(port)]["output_dir"]
        logger = Output(
            stdout=os.path.join(output_dir, "smartshield.log"),
            stderr=os.path.join(output_dir, "errors.log"),
            smartshield_logfile=os.path.join(output_dir, "smartshield.log"),
            create_logfiles=False,
        )
        conf = ConfigParser()
        try:
            return DBManager(
                logger,
                output_dir,
                port,
                conf,
                os.getpid(),  # main_pid doesn't matter here
                start_redis_server=False,
                start_sqlite=True,
                flush_db=False,
            )
        except RuntimeError:
            return


db_obj = Database()
db: DBManager = db_obj.db


def set_db_port(port):
    """sets the redis port used by the web interface"""
    db_obj.set_db(port)


def get_current_port():
    """returns the current redis port used by the web interface"""
    return db_obj.current_port


@message_sent.connect
def update_db(port):
    """is called when the user changes the used redis server from the web
    interface"""
    db_obj.set_db(port)
