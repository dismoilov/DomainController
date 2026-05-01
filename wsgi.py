"""Entry point для WSGI-серверов (gunicorn, uwsgi и т.п.)."""
from app import app as application

__all__ = ["application"]
