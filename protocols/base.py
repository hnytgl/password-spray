from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Result(Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"
    LOCKOUT = "lockout"


@dataclass
class AuthResult:
    result: Result
    target: str
    user: str
    password: str
    message: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class BaseProtocol(ABC):

    @abstractmethod
    def authenticate(self, target: str, user: str, password: str, **kwargs) -> AuthResult:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...
