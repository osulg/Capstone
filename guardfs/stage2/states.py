# states.py
from enum import Enum

class ProcState(str, Enum):
    LOW        = "LOW"
    MEDIUM     = "MEDIUM"
    HIGH       = "HIGH"
    SUSPICIOUS = "SUSPICIOUS"