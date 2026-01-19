"""
Analysis modules for IP-Sentinel.
"""

from .application import ApplicationModule
from .classification import ClassificationModule
from .internet_info import InternetInfoModule
from .local_info import LocalInfoModule

__all__ = [
    "ClassificationModule",
    "LocalInfoModule",
    "InternetInfoModule",
    "ApplicationModule",
]
