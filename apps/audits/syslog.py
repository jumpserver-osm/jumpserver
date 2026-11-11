from contextlib import contextmanager
from contextvars import ContextVar
from uuid import uuid4

from common.utils import get_syslogger
from common.utils.encode import data_to_json


relation_syslog = ContextVar('audit_relation_syslog', default=False)
logger = get_syslogger(__name__)


@contextmanager
def replacing_relation_syslog(enabled):
    token = relation_syslog.set(enabled)
    try:
        yield
    finally:
        relation_syslog.reset(token)


def write_group_membership_syslog(data, relations):
    from .models import OperateLog
    from .serializers import OperateLogSerializer
    from common.utils.timezone import local_now

    for relation in relations:
        instance = OperateLog(
            id=uuid4(), user=data['user'], action=relation['action'],
            resource_type=data['resource_type'], remote_addr=data['remote_addr'],
            org_id=relation['org_id'], datetime=local_now(),
            resource='User group {group} -> {user}'.format(**relation),
        )
        payload = dict(OperateLogSerializer(instance).data)
        payload.update(user_id=str(relation['user_id']), user_group_id=str(relation['group_id']))
        logger.info('operation_log - %s', data_to_json(payload, indent=None))
