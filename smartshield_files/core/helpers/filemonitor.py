

import os
import json
import time
from watchdog.events import RegexMatchingEventHandler


class FileEventHandler(RegexMatchingEventHandler):
    REGEX = [r".*\.log$", r".*\.conf$"]

    def __init__(self, dir_to_monitor, db, pcap_or_interface):
        super().__init__(regexes=self.REGEX)
        self.dir_to_monitor = dir_to_monitor
        # name of the pcap or interface zeek is monitoring
        self.pcap_or_interface = pcap_or_interface
        self.db = db

    def on_created(self, event):
        """this will be triggered everytime zeek creates a log file"""
        filename, ext = os.path.splitext(event.src_path)
        if "log" in ext:
            self.db.add_zeek_file(filename + ext, self.pcap_or_interface)

    def on_moved(self, event):
        """
        this will be triggered everytime zeek renames all log files
        """
        # tell inputProcess to change open handles
        if event.dest_path != "True":
            to_send = {"old_file": event.dest_path, "new_file": event.src_path}
            to_send = json.dumps(to_send)
            self.db.publish("remove_old_files", to_send)

            # give inputProc.py time to close the handle or delete the file
            time.sleep(1)

    def on_modified(self, event):
        """
        this will be triggered everytime zeek modifies a log file
        """
        # we only need to know modifications to reporter.log,
        # so if zeek receives a termination signal,
        # smartshield would know about it
        filename, ext = os.path.splitext(event.src_path)

        if "reporter" in filename:
            # check if it's a termination signal
            # get the exact file name (a ts is appended to it)
            for file in os.listdir(self.dir_to_monitor):
                if "reporter" not in file:
                    continue
                with open(os.path.join(self.dir_to_monitor, file), "r") as f:
                    while line := f.readline():
                        if "termination" in line:
                            # tell smartshield to terminate
                            self.db.publish_stop()
                            break
