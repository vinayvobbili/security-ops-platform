"""Base command classes for Webex bots.

This package provides reusable base classes for Webex bot commands,
reducing boilerplate and ensuring consistency across command implementations.
"""

from .aide_command import NotificationCommand, CardOnlyCommand

# Alias: command modules subclass AideCommand as their logging-enabled base.
AideCommand = NotificationCommand

__all__ = ['NotificationCommand', 'CardOnlyCommand', 'AideCommand']
