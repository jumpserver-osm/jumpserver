"""Isolated source-boundary tests; never connect to application services.

Run: python -m unittest discover -s tests/audits -p 'test_*.py' -v
Requires Django and Django REST Framework. Minimal SQLite models exercise real
signals and serializer updates; audit functions are loaded from repository source.
"""
import ast
import copy
import json
import re
from contextlib import nullcontext
from datetime import datetime
from itertools import chain
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import django
from django.conf import settings

if settings.configured:
    raise RuntimeError('Run audit boundary tests in a standalone process')
settings.configure(
    SECRET_KEY='isolated-audit-regression-tests', USE_I18N=False,
    INSTALLED_APPS=['django.contrib.contenttypes', 'audit_test_app'],
    DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': ':memory:'}},
    CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}},
    REST_FRAMEWORK={'UNAUTHENTICATED_USER': None},
)
django.setup()

from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.db import models, transaction
from django.db.models.signals import m2m_changed, pre_save, pre_delete, post_save
from rest_framework import serializers
from audit_test_app.models import OperateLog

ROOT = Path(__file__).resolve().parents[2]


def load(path, names, namespace):
    tree = ast.parse((ROOT / path).read_text())
    body = [node for node in tree.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names]
    exec(compile(ast.Module(body=body, type_ignores=[]), str(ROOT / path), 'exec'), namespace)
    return namespace


utils = load('apps/audits/utils.py', [
    '_get_instance_field_value', 'model_to_dict_for_operate_log',
], dict(copy=copy, datetime=datetime, chain=chain, models=models,
        GenericForeignKey=GenericForeignKey, GenericRelation=GenericRelation,
        ObjectDoesNotExist=ObjectDoesNotExist, RelatedManager=type('RelatedManager', (), {}),
        as_current_tz=lambda value: value))

choices = SimpleNamespace(update='update', create='create', delete='delete')
request = SimpleNamespace(user=SimpleNamespace(is_authenticated=True, is_service_account=False))
handler_ns = load('apps/audits/handler.py', ['OperatorLogHandler'], dict(
    Singleton=type, datetime=datetime, as_current_tz=lambda value: value,
    similar_encrypted_pattern=re.compile('password|secret|token'),
    exclude_encrypted_fields=(), _=lambda value: value, current_request=request, json=json,
    cache=cache, transaction=transaction, get_request_ip=lambda req: '127.0.0.1',
    Organization=SimpleNamespace(SYSTEM_ID='system', DEFAULT_ID='org-1'),
    get_current_org_id=lambda: 'org-1', Setting=type('Setting', (), {}),
    Preference=type('Preference', (), {}), logger=Mock(),
))
handler = object.__new__(handler_ns['OperatorLogHandler'])
DBStore = load('apps/audits/backends/db.py', ['OperateLogStore'], dict(
    _=lambda value: value, ActionChoices=choices, OperateLog=OperateLog,
))['OperateLogStore']
ESStore = load('apps/audits/backends/es.py', ['OperateLogStore'], dict(
    ES=object, Singleton=type,
))['OperateLogStore']

signals = load('apps/audits/signal_handlers/operate_log.py', [
    '_get_m2m_audit_field', 'on_m2m_changed',
    'on_object_pre_create_or_update', 'on_object_created_or_update',
], dict(
    receiver=lambda *a, **k: lambda f: f, m2m_changed=m2m_changed,
    pre_save=pre_save, pre_delete=pre_delete, post_save=post_save,
    translation=SimpleNamespace(override=lambda _: nullcontext()),
    model_to_dict=utils['model_to_dict_for_operate_log'],
    PRE_ADD='pre_add', PRE_REMOVE='pre_remove', PRE_CLEAR='pre_clear',
    POST_ADD='post_add', POST_REMOVE='post_remove', POST_CLEAR='post_clear',
    ActionChoices=choices,
    get_instance_dict_from_cache=handler.get_instance_dict_from_cache,
    cache_instance_before_data=handler.cache_instance_before_data,
    get_instance_current_with_cache_diff=handler.get_instance_current_with_cache_diff,
    create_or_update_operate_log=handler.create_or_update_operate_log,
    signal_of_operate_log_whether_continue=lambda *a: False,
    uuid=__import__('uuid'),
))
