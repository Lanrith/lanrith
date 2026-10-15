#!/usr/bin/env python3
"""BIND's TSIG policy for the shared private activation journal."""

from pathlib import Path
import credential_runtime
from credential_runtime import Activation, PHASES, TEMPORARY_PREFIX
from tsig import TSIGError, validate


def read_json(raw):
    try:
        return credential_runtime.read_json(raw)
    except ValueError as error:
        raise TSIGError('BIND runtime JSON is invalid or ambiguous.') from error


class State(credential_runtime.State):
    Error = TSIGError

    def __init__(self, root=Path('/var/lib/lanrith/bind'), owner=0, group=0):
        super().__init__(root, owner, group)

    def validate(self, raw):
        try:
            return validate(raw.decode('ascii')).encode('ascii') + b'\n'
        except UnicodeError as error:
            raise TSIGError('BIND source is not canonical Base64.') from error
