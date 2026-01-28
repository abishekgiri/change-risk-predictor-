from abc import ABC, abstractmethod
from typing import Set
from .types import EnforcementAction, EnforcementResult, ActionType

class Enforcer(ABC):
    """
    Abstract base class for all enforcement mechanisms (GitHub, Jira, etc).
    """
    
    @abstractmethod
    def supported_actions(self) -> Set[ActionType]:
        """Return the set of actions this enforcer handles."""
        pass

    @abstractmethod
    def execute(self, action: EnforcementAction) -> EnforcementResult:
        """Execute the action and return the result."""
        pass
