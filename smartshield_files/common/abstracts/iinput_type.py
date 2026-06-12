 
 
from abc import ABC, abstractmethod


class IInputType(ABC):
    """
    Interface for all input types supported by smartshield placed in smartshield_files/core/profiler.py
    """

    @abstractmethod
    def process_line(self, line: str):
        """
        Process all fields of a given line
        """
