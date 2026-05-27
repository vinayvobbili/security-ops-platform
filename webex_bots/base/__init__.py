"""Base command classes for Webex bots.

This package provides reusable base classes for Webex bot commands,
reducing boilerplate and ensuring consistency across command implementations.
"""

from .toodles_command import NotificationCommand, CardOnlyCommand

__all__ = ['NotificationCommand', 'CardOnlyCommand']
