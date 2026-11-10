import copy
import json
import unittest
import uuid
import warnings
from types import SimpleNamespace
from unittest.mock import Mock, patch

from support import (
    DBStore, ESStore, RelationMixin, cache, handler, signals, utils,
    handler_ns, syslog_ns, other_ns, operate_serializer, request,
)
from datetime import datetime
from django.apps import apps
from django.core.cache import CacheKeyWarning
from django.db import connection
from django.db.models.signals import m2m_changed, pre_save, post_save, pre_delete, post_delete
from rest_framework.serializers import ModelSerializer
from audit_test_app.models import (
    User, Group, OperateLog, AssetPermission, Role, CommandACL, Host, BackupPlan, FieldValues,
)


class AuditRegressionTests(unittest.TestCase):
    relation_api_paths = [
        (User, 'groups', 'User group'),
        (AssetPermission, 'users', 'User'),
        (AssetPermission, 'user_groups', 'User group'),
        (AssetPermission, 'assets', 'Asset'),
        (AssetPermission, 'nodes', 'Node'),
    ]

    @classmethod
    def setUpClass(cls):
        cls.models = list(apps.get_app_config('audit_test_app').get_models())
        with connection.schema_editor() as editor:
            for model in cls.models:
                editor.create_model(model)
        for model in cls.models:
            if model is OperateLog:
                continue
            pre_save.connect(signals['on_object_pre_create_or_update'], sender=model, weak=False)
            post_save.connect(signals['on_object_created_or_update'], sender=model, weak=False)
            pre_delete.connect(signals['on_object_pre_create_or_update'], sender=model, weak=False)
            post_delete.connect(signals['on_object_delete'], sender=model, weak=False)
            for field in model._meta.local_many_to_many:
                m2m_changed.connect(signals['on_m2m_changed'], sender=field.remote_field.through, weak=False)

    @classmethod
    def tearDownClass(cls):
        for model in cls.models:
            pre_save.disconnect(signals['on_object_pre_create_or_update'], sender=model)
            post_save.disconnect(signals['on_object_created_or_update'], sender=model)
            pre_delete.disconnect(signals['on_object_pre_create_or_update'], sender=model)
            post_delete.disconnect(signals['on_object_delete'], sender=model)
            for field in model._meta.local_many_to_many:
                m2m_changed.disconnect(signals['on_m2m_changed'], sender=field.remote_field.through)
        with connection.schema_editor() as editor:
            for model in reversed(cls.models):
                editor.delete_model(model)

    def setUp(self):
        self.warnings = warnings.catch_warnings()
        self.warnings.__enter__()
        self.addCleanup(self.warnings.__exit__, None, None, None)
        # The existing handler uses the serialized ID dict in its cache key.
        warnings.simplefilter('ignore', CacheKeyWarning)
        self.enabled = False
        signals['signal_of_operate_log_whether_continue'] = lambda sender, *a: self.enabled and sender is not OperateLog
        signals['create_or_update_operate_log'] = lambda *a, **kw: handler.create_or_update_operate_log(*a, **kw) if self.enabled else None
        handler.log_client = DBStore({})
        self.reset_logs()

    def reset_logs(self):
        cache.clear()
        OperateLog.objects.all().delete()
        handler_ns_logger = handler.create_or_update_operate_log.__globals__['logger']
        handler_ns_logger.reset_mock()

    def assert_no_log_errors(self):
        handler.create_or_update_operate_log.__globals__['logger'].error.assert_not_called()

    def prepare(self, model, field, initial, final):
        self.enabled = False
        related_model = model._meta.get_field(field).related_model
        members = {name: related_model.objects.create(name=name) for name in set(initial) | set(final)}
        instance = model.objects.create(name='resource')
        getattr(instance, field).set([members[name] for name in initial])
        self.reset_logs()
        self.enabled = True
        return instance, members

    def edit(self, instance, **data):
        relations = {field.name for field in instance._meta.get_fields() if field.many_to_many}
        meta = type('Meta', (), {
            'model': type(instance), 'fields': tuple(data),
            'extra_kwargs': {name: {'allow_empty': True} for name in data if name in relations},
        })
        editor = type('Editor', (ModelSerializer,), {'Meta': meta})
        serializer = editor(instance, data=data, partial=True)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        serializer.save()
        self.assert_no_log_errors()

    def assert_log(self, label, before, after, resource_type=None):
        self.assert_no_log_errors()
        self.assertEqual(OperateLog.objects.count(), 1)
        log = OperateLog.objects.get()
        old, new = DBStore.convert_diff_to_before_after(log.diff)
        self.assertEqual(old[label].split(',') if old[label] else [], sorted(before))
        self.assertEqual(new[label].split(',') if new[label] else [], sorted(after))
        if resource_type:
            self.assertEqual(log.resource_type, resource_type)
        return old, new

    def relation_api(self, model, field):
        return type('RelationAPI', (RelationMixin,), {
            'm2m_field': model._meta.get_field(field),
        })()

    def create_relations(self, api, pairs, many=True):
        meta = type('Meta', (), {
            'model': api.through, 'fields': (api.from_field, api.to_field),
        })
        serializer_cls = type('RelationSerializer', (ModelSerializer,), {'Meta': meta})
        data = [{api.from_field: instance.pk, api.to_field: member.pk}
                for instance, member in pairs]
        serializer = serializer_cls(data=data if many else data[0], many=many)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        api.perform_create(serializer)
        self.assert_no_log_errors()
        return serializer.instance if many else [serializer.instance]

    def post_only_change(self, instance, accessor, action, members):
        relation = instance._meta.get_field(accessor)
        reverse = relation.auto_created
        field = relation.field if reverse else relation
        from_field, to_field = field.m2m_field_name(), field.m2m_reverse_field_name()
        if reverse:
            from_field, to_field = to_field, from_field
        through = field.remote_field.through
        if action == 'post_add':
            through.objects.bulk_create([
                through(**{from_field: instance, to_field: member}) for member in members
            ])
        else:
            through.objects.filter(**{
                from_field: instance, to_field + '__in': members,
            }).delete()
        m2m_changed.send(
            sender=through, instance=instance, action=action, reverse=reverse,
            model=relation.related_model, pk_set={member.pk for member in members},
            using='default',
        )
        self.assert_no_log_errors()

    def capture_membership_syslog(self):
        modules = {
            'audits.models': SimpleNamespace(OperateLog=OperateLog),
            'audits.serializers': SimpleNamespace(OperateLogSerializer=operate_serializer),
            'common.utils.timezone': SimpleNamespace(local_now=lambda: datetime(2026, 11, 10, 12)),
        }
        self.enterContext(patch.dict('sys.modules', modules))
        self.enterContext(patch.dict(handler_ns, {
            'write_group_membership_syslog': syslog_ns['write_group_membership_syslog'],
        }))
        self.enterContext(patch.dict(syslog_ns, {'logger': Mock()}))
        self.enterContext(patch.dict(other_ns, {'sys_logger': Mock()}))
        post_save.connect(other_ns['on_audits_log_create'], sender=OperateLog, weak=False)
        self.addCleanup(post_save.disconnect, other_ns['on_audits_log_create'], sender=OperateLog)
        return syslog_ns['logger'], other_ns['sys_logger']

    def membership_messages(self, logger):
        return [json.loads(call.args[1]) for call in logger.info.call_args_list]

    def test_membership_syslog_replacement_keeps_one_page_log(self):
        instance, members = self.prepare(User, 'groups', ['A'], ['B'])
        detailed, ordinary = self.capture_membership_syslog()
        self.edit(instance, groups=[members['B'].pk])
        self.assert_log('User group', ['A'], ['B'], 'User')
        messages = self.membership_messages(detailed)
        self.assertEqual([m['action']['value'] for m in messages], ['delete', 'create'])
        self.assertEqual([m['user_group_id'] for m in messages],
                         [str(members['A'].pk), str(members['B'].pk)])
        self.assertEqual(len({m['id'] for m in messages}), 2)
        for m in messages:
            self.assertEqual(m['user_id'], str(instance.pk))
            self.assertEqual(m['resource_type'], 'User')
            self.assertEqual(m['remote_addr'], '127.0.0.1')
            self.assertEqual(m['org_id'], 'org-1')
            self.assertEqual(m['user'], str(request.user))
            self.assertIn(str(instance), m['resource'])
        ordinary.info.assert_not_called()
        self.assertFalse(syslog_ns['relation_syslog'].get())

    def test_membership_syslog_reverse_batch_clear_and_unchanged(self):
        group, users = self.prepare(Group, 'users', [], ['U1', 'U2'])
        detailed, ordinary = self.capture_membership_syslog()
        self.edit(group, users=[u.pk for u in users.values()])
        self.assert_log('User', [], ['U1', 'U2'], 'User group')
        messages = self.membership_messages(detailed)
        self.assertEqual({m['user_id'] for m in messages}, {str(u.pk) for u in users.values()})
        self.assertTrue(all(m['user_group_id'] == str(group.pk) and
                            m['action']['value'] == 'create' for m in messages))
        detailed.reset_mock()
        self.edit(group, users=[u.pk for u in users.values()])
        detailed.info.assert_not_called()
        group.users.clear()
        self.assertEqual([m['action']['value'] for m in self.membership_messages(detailed)],
                         ['delete', 'delete'])
        self.assertEqual(group.users.count(), 0)
        ordinary.info.assert_not_called()

    def test_membership_syslog_relation_api_and_add_all_no_duplicates(self):
        group, users = self.prepare(Group, 'users', [], ['U1', 'U2'])
        detailed, ordinary = self.capture_membership_syslog()
        api = self.relation_api(User, 'groups')
        relations = self.create_relations(api, [(users['U1'], group)], many=False)
        api.perform_destroy(relations[0])
        self.assertEqual([m['action']['value'] for m in self.membership_messages(detailed)],
                         ['create', 'delete'])
        detailed.reset_mock()
        group.users.add(*users.values())
        self.assertEqual(detailed.info.call_count, 2)
        group.users.add(*users.values())
        self.assertEqual(detailed.info.call_count, 2)
        ordinary.info.assert_not_called()

    def test_membership_syslog_preserves_scalar_and_unrelated_logs(self):
        instance, members = self.prepare(User, 'groups', ['A'], ['B'])
        detailed, ordinary = self.capture_membership_syslog()
        self.edit(instance, name='renamed', groups=[members['B'].pk])
        self.assertEqual(detailed.info.call_count, 2)
        ordinary.info.assert_called_once()
        self.assertEqual(DBStore.convert_diff_to_before_after(OperateLog.objects.get().diff),
                         ({'Name': 'resource', 'User group': 'A'},
                          {'Name': 'renamed', 'User group': 'B'}))
        detailed.reset_mock()
        ordinary.reset_mock()
        instance, members = self.prepare(AssetPermission, 'users', [], ['U'])
        self.edit(instance, users=[members['U'].pk])
        detailed.info.assert_not_called()
        ordinary.info.assert_called_once()

    def test_membership_syslog_relation_api_batch_and_user_clear(self):
        instance, groups = self.prepare(User, 'groups', [], ['A', 'B'])
        detailed, ordinary = self.capture_membership_syslog()
        api = self.relation_api(User, 'groups')
        self.create_relations(api, [(instance, group) for group in groups.values()])
        self.assertEqual({m['user_group_id'] for m in self.membership_messages(detailed)},
                         {str(group.pk) for group in groups.values()})
        self.assertEqual(detailed.info.call_count, 2)
        detailed.reset_mock()
        instance.groups.clear()
        self.assertEqual([m['action']['value'] for m in self.membership_messages(detailed)],
                         ['delete', 'delete'])
        self.assertEqual(instance.groups.count(), 0)
        ordinary.info.assert_not_called()

    def test_membership_syslog_reverse_replacement(self):
        group, users = self.prepare(Group, 'users', ['U1'], ['U2'])
        detailed, ordinary = self.capture_membership_syslog()
        self.edit(group, users=[users['U2'].pk])
        self.assert_log('User', ['U1'], ['U2'], 'User group')
        messages = self.membership_messages(detailed)
        self.assertEqual([(m['action']['value'], m['user_id']) for m in messages],
                         [('delete', str(users['U1'].pk)), ('create', str(users['U2'].pk))])
        self.assertTrue(all(m['resource_type'] == 'User group' for m in messages))
        ordinary.info.assert_not_called()

    def test_membership_syslog_same_named_replacement_uses_ids(self):
        instance, members = self.prepare(User, 'groups', ['same'], [])
        self.enabled = False
        duplicate = Group.objects.create(name='same')
        self.reset_logs()
        self.enabled = True
        detailed, ordinary = self.capture_membership_syslog()
        self.edit(instance, groups=[duplicate.pk])
        messages = self.membership_messages(detailed)
        self.assertEqual([(m['action']['value'], m['user_group_id']) for m in messages],
                         [('delete', str(members['same'].pk)), ('create', str(duplicate.pk))])
        self.assertEqual(list(instance.groups.values_list('pk', flat=True)), [duplicate.pk])
        ordinary.info.assert_not_called()

    def test_membership_syslog_failure_restores_normal_output(self):
        instance, members = self.prepare(User, 'groups', [], ['A'])
        detailed, ordinary = self.capture_membership_syslog()
        self.enterContext(patch.object(detailed, 'info', side_effect=OSError('syslog unavailable')))
        self.edit(instance, groups=[members['A'].pk])
        self.assertEqual(instance.groups.count(), 1)
        self.assertEqual(OperateLog.objects.count(), 1)
        handler_ns['logger'].exception.assert_called_once()
        self.assertFalse(syslog_ns['relation_syslog'].get())
        self.edit(instance, name='new')
        ordinary.info.assert_called_once()

    def test_membership_syslog_not_sent_after_storage_failure_or_without_actor(self):
        instance, members = self.prepare(User, 'groups', [], ['A'])
        detailed, ordinary = self.capture_membership_syslog()
        handler.log_client = Mock(ping=Mock(return_value=True), save=Mock(side_effect=ValueError('store failed')))
        instance.groups.add(members['A'])
        detailed.info.assert_not_called()
        self.assertFalse(syslog_ns['relation_syslog'].get())
        handler_ns['logger'].error.assert_called_once()
        self.enterContext(patch.object(request.user, 'is_authenticated', False))
        instance.groups.clear()
        detailed.info.assert_not_called()
        ordinary.info.assert_not_called()

    def test_membership_syslog_works_without_database_post_save(self):
        instance, members = self.prepare(User, 'groups', [], ['A'])
        detailed, ordinary = self.capture_membership_syslog()
        store = object.__new__(ESStore)
        store.es = Mock()
        store.index, store.doc_type = 'test', '_doc'
        store.get = Mock(return_value=None)
        store.ping = lambda timeout=None: True
        handler.log_client = store
        self.edit(instance, groups=[members['A'].pk])
        store.es.index.assert_called_once()
        self.assertEqual(store.es.index.call_args.kwargs['body']['after'], {'User group': 'A'})
        self.assertEqual(len(self.membership_messages(detailed)), 1)
        self.assertEqual(OperateLog.objects.count(), 0)
        ordinary.info.assert_not_called()

    def test_membership_syslog_preserves_other_audit_categories_and_context(self):
        _, ordinary = self.capture_membership_syslog()
        login = Mock(data={'username': 'actor', 'status': 'success'})
        self.enterContext(patch.dict(other_ns, {'UserLoginLogSerializer': Mock(return_value=login)}))
        with syslog_ns['replacing_relation_syslog'](True):
            other_ns['on_audits_log_create'](other_ns['UserLoginLog'], instance=object())
            with syslog_ns['replacing_relation_syslog'](False):
                self.assertFalse(syslog_ns['relation_syslog'].get())
            self.assertTrue(syslog_ns['relation_syslog'].get())
        self.assertFalse(syslog_ns['relation_syslog'].get())
        ordinary.info.assert_called_once_with(
            'login_log - ' + json.dumps({'username': 'actor', 'status': 'success'}),
        )

    def test_relation_api_add_and_remove_single_and_bulk(self):
        for model, field, label in self.relation_api_paths:
            for count in (1, 2):
                for initial in ([], ['kept']):
                    with self.subTest(model=model.__name__, field=field,
                                      count=count, initial=initial):
                        added = ['added-' + str(i) for i in range(count)]
                        instance, members = self.prepare(model, field, initial, added)
                        api = self.relation_api(model, field)
                        relations = self.create_relations(
                            api, [(instance, members[name]) for name in added], many=count > 1,
                        )
                        self.assert_log(label, initial, initial + added,
                                        str(model._meta.verbose_name))
                        log = OperateLog.objects.get()
                        self.assertEqual(log.resource, str(instance))
                        self.assertEqual(log.resource_id, str(instance.pk))
                        self.assertEqual(log.action, 'update')
                        remaining = initial + added
                        for name, relation in zip(added, relations):
                            self.reset_logs()
                            previous = list(remaining)
                            api.perform_destroy(relation)
                            remaining.remove(name)
                            self.assert_log(label, previous, remaining,
                                            str(model._meta.verbose_name))
                            self.assertEqual(
                                sorted(getattr(instance, field).values_list('name', flat=True)),
                                sorted(remaining),
                            )
                        self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))

    def test_relation_api_batch_keeps_parent_resources_separate(self):
        for model, field, label in self.relation_api_paths:
            with self.subTest(model=model.__name__, field=field):
                first, members = self.prepare(model, field, ['kept'], ['A', 'B'])
                self.enabled = False
                second = model.objects.create(name='second')
                self.reset_logs()
                self.enabled = True
                api = self.relation_api(model, field)
                self.create_relations(api, [
                    (first, members['A']), (second, members['B']), (first, members['B']),
                ])
                self.assertEqual(OperateLog.objects.count(), 2)
                for instance, before, after in [
                    (first, ['kept'], ['A', 'B', 'kept']), (second, [], ['B']),
                ]:
                    log = OperateLog.objects.get(resource_id=str(instance.pk))
                    self.assertEqual(DBStore.convert_diff_to_before_after(log.diff),
                                     ({label: ','.join(before)}, {label: ','.join(after)}))
                    self.assertEqual(log.resource_type, str(model._meta.verbose_name))
                    self.assertEqual(sorted(getattr(instance, field).values_list('name', flat=True)),
                                     after)

    def test_relation_api_remove_without_preceding_add(self):
        for model, field, label in self.relation_api_paths:
            for initial in (['removed'], ['kept', 'removed']):
                with self.subTest(model=model.__name__, field=field, initial=initial):
                    instance, members = self.prepare(model, field, initial, [])
                    api = self.relation_api(model, field)
                    relation = api.through.objects.get(**{
                        api.from_field: instance, api.to_field: members['removed'],
                    })
                    api.perform_destroy(relation)
                    remaining = [name for name in initial if name != 'removed']
                    self.assert_log(label, initial, remaining, str(model._meta.verbose_name))
                    self.assertEqual(list(getattr(instance, field).values_list('name', flat=True)),
                                     remaining)

    def test_post_only_reverse_and_distinct_relations(self):
        for model, field, label in [
            (Group, 'users', 'User'),
            (BackupPlan, 'recipients_one', 'Recipient one'),
            (BackupPlan, 'recipients_two', 'Recipient two'),
        ]:
            with self.subTest(model=model.__name__, field=field):
                instance, members = self.prepare(model, field, ['kept'], ['added'])
                self.post_only_change(instance, field, 'post_add', [members['added']])
                before, after = self.assert_log(label, ['kept'], ['added', 'kept'],
                                               str(model._meta.verbose_name))
                self.assertEqual(set(before), {label})
                self.assertEqual(set(after), {label})
                self.reset_logs()
                self.post_only_change(instance, field, 'post_remove', list(members.values()))
                self.assert_log(label, ['added', 'kept'], [], str(model._meta.verbose_name))
                self.assertEqual(getattr(instance, field).count(), 0)
                self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))

    def test_post_only_duplicate_display_names_keep_distinct_ids(self):
        for model, field, label in [(User, 'groups', 'User group'), (Group, 'users', 'User')]:
            with self.subTest(model=model.__name__):
                instance, members = self.prepare(model, field, ['same'], [])
                self.enabled = False
                duplicate = model._meta.get_field(field).related_model.objects.create(name='same')
                self.reset_logs()
                self.enabled = True
                self.post_only_change(instance, field, 'post_add', [duplicate])
                self.assert_log(label, ['same'], ['same', 'same'])
                self.reset_logs()
                self.post_only_change(instance, field, 'post_remove', [members['same']])
                self.assert_log(label, ['same', 'same'], ['same'])
                self.assertEqual(list(getattr(instance, field).values_list('pk', flat=True)),
                                 [duplicate.pk])

    def test_post_only_missing_changes_do_not_fabricate_logs(self):
        instance, members = self.prepare(User, 'groups', ['kept'], ['unrelated'])
        kwargs = dict(sender=User.groups.through, instance=instance, reverse=False,
                      model=Group, using='default')
        for action, pk_set in [
            ('post_add', set()), ('post_remove', set()),
            ('post_add', None), ('post_remove', None),
            ('post_add', {-1}), ('post_remove', {-1}),
            ('post_add', {members['unrelated'].pk}),
            ('post_remove', {members['kept'].pk}),
            ('post_clear', None),
        ]:
            with self.subTest(action=action, pk_set=pk_set):
                m2m_changed.send(action=action, pk_set=pk_set, **kwargs)
                self.assertEqual(OperateLog.objects.count(), 0)
                self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))
        self.assertEqual(list(instance.groups.values_list('pk', flat=True)), [members['kept'].pk])

    def test_pre_snapshot_takes_priority_over_post_only_fallback(self):
        instance, members = self.prepare(User, 'groups', ['A'], ['B'])
        kwargs = dict(sender=User.groups.through, instance=instance, reverse=False,
                      model=Group, using='default')
        m2m_changed.send(action='pre_remove', pk_set={members['A'].pk}, **kwargs)
        User.groups.through.objects.filter(user=instance, usergroup=members['A']).delete()
        m2m_changed.send(action='post_remove', pk_set=set(), **kwargs)
        self.assert_log('User group', ['A'], [])
        self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))

    def test_post_only_changes_reach_elasticsearch_with_correct_values(self):
        for model, field, label in self.relation_api_paths:
            with self.subTest(model=model.__name__, field=field):
                instance, members = self.prepare(model, field, ['kept'], ['added'])
                store = object.__new__(ESStore)
                store.es = Mock()
                store.index, store.doc_type = 'test', '_doc'
                store.get = Mock(return_value=None)
                store.ping = lambda timeout=None: True
                handler.log_client = store
                api = self.relation_api(model, field)
                relations = self.create_relations(api, [(instance, members['added'])], many=False)
                store.es.index.assert_called_once()
                data = store.es.index.call_args.kwargs['body']
                self.assertEqual(data['before'], {label: 'kept'})
                self.assertEqual(data['after'], {label: 'added,kept'})
                self.assertEqual(data['resource_type'], str(model._meta.verbose_name))
                self.assertEqual(data['action'], 'update')
                store.es.reset_mock()
                api.perform_destroy(relations[0])
                self.assert_no_log_errors()
                store.es.index.assert_called_once()
                data = store.es.index.call_args.kwargs['body']
                self.assertEqual(data['before'], {label: 'added,kept'})
                self.assertEqual(data['after'], {label: 'kept'})
                self.assertEqual(list(getattr(instance, field).values_list('name', flat=True)), ['kept'])

    def test_post_only_replacement_merges_initial_and_final_values_in_both_stores(self):
        for backend in ('db', 'es'):
            with self.subTest(backend=backend):
                instance, members = self.prepare(User, 'groups', ['A'], ['B'])
                # Save first to give both post-only events the same operation-log ID.
                instance.save()
                if backend == 'es':
                    store = object.__new__(ESStore)
                    store.es = Mock()
                    store.index, store.doc_type = 'test', '_doc'
                    store.ping = lambda timeout=None: True
                    document = {}
                    store.get = lambda query: copy.deepcopy(document) if document else None
                    store.es.index.side_effect = lambda **kw: document.update(
                        copy.deepcopy(kw['body']), es_id='doc-1',
                    )
                    store.es.update.side_effect = lambda **kw: document.update(
                        copy.deepcopy(kw['body']['doc']),
                    )
                    handler.log_client = store
                self.post_only_change(instance, 'groups', 'post_remove', [members['A']])
                self.post_only_change(instance, 'groups', 'post_add', [members['B']])
                if backend == 'db':
                    self.assert_log('User group', ['A'], ['B'], 'User')
                else:
                    store.es.index.assert_called_once()
                    store.es.update.assert_called_once()
                    self.assertEqual(document['before'], {'User group': 'A'})
                    self.assertEqual(document['after'], {'User group': 'B'})
                    self.assertEqual(document['resource_type'], 'User')
                self.assertEqual(list(instance.groups.values_list('pk', flat=True)), [members['B'].pk])
                self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))

    def test_relation_edits_preserve_business_state_and_final_log(self):
        paths = [
            (User, 'groups', 'User group'), (Group, 'users', 'User'),
            (AssetPermission, 'users', 'User'), (AssetPermission, 'user_groups', 'User group'),
            (AssetPermission, 'assets', 'Asset'), (AssetPermission, 'nodes', 'Node'),
            (Role, 'permissions', 'Permissions'), (CommandACL, 'command_groups', 'Command group'),
            (CommandACL, 'reviewers', 'Reviewers'), (Host, 'nodes', 'Nodes'),
        ]
        scenarios = [(['A'], ['B']), (['A', 'B'], ['B', 'C']),
                     (['A'], ['A', 'B']), (['A', 'B'], ['B']), (['A'], []),
                     ([], ['B']), (['A'], ['A']), ([], [])]
        for model, field, label in paths:
            for before, after in scenarios:
                with self.subTest(model=model.__name__, field=field, before=before, after=after):
                    instance, members = self.prepare(model, field, before, after)
                    self.edit(instance, **{field: [members[name].pk for name in after]})
                    self.assertEqual(sorted(getattr(instance, field).values_list('name', flat=True)), sorted(after))
                    self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))
                    if before == after:
                        self.assertEqual(OperateLog.objects.count(), 0)
                    else:
                        self.assert_log(label, before, after, str(model._meta.verbose_name))

    def test_replace_then_remove_or_clear_same_log_id(self):
        for method in ('remove', 'clear'):
            with self.subTest(method=method):
                instance, members = self.prepare(User, 'groups', ['A'], ['B'])
                self.edit(instance, groups=[members['B'].pk])
                if method == 'remove':
                    instance.groups.remove(members['B'])
                else:
                    instance.groups.clear()
                self.assertEqual(instance.groups.count(), 0)
                self.assert_log('User group', ['A'], [])
                self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))

    def test_direct_clear_forward_and_reverse(self):
        for model, field, label in [(User, 'groups', 'User group'), (Group, 'users', 'User')]:
            with self.subTest(model=model.__name__):
                instance, _ = self.prepare(model, field, ['A', 'B'], [])
                getattr(instance, field).clear()
                self.assertEqual(getattr(instance, field).count(), 0)
                self.assert_log(label, ['A', 'B'], [])

    def test_clear_then_add_and_repeated_replacements(self):
        for clear_first in (False, True):
            with self.subTest(clear_first=clear_first):
                instance, members = self.prepare(User, 'groups', ['A'], ['B', 'C'])
                instance.save()
                if clear_first:
                    instance.groups.clear()
                    instance.groups.add(members['B'])
                else:
                    instance.groups.set([members['B']])
                instance.groups.set([members['C']])
                self.assertEqual(list(instance.groups.values_list('name', flat=True)), ['C'])
                self.assert_log('User group', ['A'], ['C'])

    def test_unchanged_values_with_duplicate_display_names(self):
        instance, members = self.prepare(User, 'groups', ['A'], [])
        self.enabled = False
        other = Group.objects.create(name='A')
        instance.groups.add(other)
        self.reset_logs()
        self.enabled = True
        self.edit(instance, groups=[members['A'].pk])
        self.assertEqual(instance.groups.count(), 1)
        self.assert_log('User group', ['A', 'A'], ['A'])

    def test_direct_relation_without_saved_log_id_remains_two_logs(self):
        instance, members = self.prepare(User, 'groups', ['A'], ['B'])
        instance.groups.set([members['B']])
        self.assertEqual(OperateLog.objects.count(), 2)
        self.assertEqual(list(instance.groups.values_list('name', flat=True)), ['B'])
        self.assert_no_log_errors()

    def test_multiple_fields_and_relations_do_not_overwrite(self):
        instance, users = self.prepare(AssetPermission, 'users', ['UserA'], ['UserB'])
        self.enabled = False
        a = Group.objects.create(name='GroupA')
        b = Group.objects.create(name='GroupB')
        instance.user_groups.add(a)
        self.reset_logs()
        self.enabled = True
        self.edit(instance, name='new', users=[users['UserB'].pk], user_groups=[b.pk])
        before, after = self.assert_log('User', ['UserA'], ['UserB'], 'Asset permission')
        self.assertEqual(before['Name'], 'resource')
        self.assertEqual(after['Name'], 'new')
        self.assertEqual(before['User group'], 'GroupA')
        self.assertEqual(after['User group'], 'GroupB')
        instance.refresh_from_db()
        self.assertEqual(instance.name, 'new')
        self.assertEqual(list(instance.user_groups.values_list('name', flat=True)), ['GroupB'])

    def test_two_relations_to_same_model_do_not_mix(self):
        instance, first = self.prepare(BackupPlan, 'recipients_one', ['A'], ['B'])
        self.enabled = False
        a = User.objects.create(name='C')
        b = User.objects.create(name='D')
        instance.recipients_two.add(a)
        self.reset_logs()
        self.enabled = True
        self.edit(instance, recipients_one=[first['B'].pk], recipients_two=[b.pk])
        before, after = self.assert_log('Recipient one', ['A'], ['B'])
        self.assertEqual(before['Recipient two'], 'C')
        self.assertEqual(after['Recipient two'], 'D')
        self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))

    def test_snapshots_are_isolated_by_instance_and_relation(self):
        first, members = self.prepare(User, 'groups', ['A'], [])
        self.enabled = False
        second = User.objects.create(name='second')
        second.groups.add(members['A'])
        self.enabled = True
        signal = signals['on_m2m_changed']
        kwargs = dict(sender=User.groups.through, action='pre_clear', reverse=False,
                      model=Group, pk_set=None, using='default')
        signal(instance=first, **kwargs)
        signal(instance=second, **kwargs)
        first.groups.clear()
        self.assertFalse(hasattr(first, '_operate_log_m2m_snapshots'))
        self.assertTrue(hasattr(second, '_operate_log_m2m_snapshots'))
        second.groups.clear()
        self.assertFalse(hasattr(second, '_operate_log_m2m_snapshots'))

    def test_aborted_pre_event_is_overwritten_and_empty_clear_is_noop(self):
        instance, members = self.prepare(User, 'groups', ['A'], ['B'])
        signals['on_m2m_changed'](
            sender=User.groups.through, instance=instance, action='pre_clear',
            reverse=False, model=Group, pk_set=None, using='default',
        )
        # Simulate an aborted clear; the next real pre event must replace its snapshot.
        self.edit(instance, groups=[members['B'].pk])
        self.assert_log('User group', ['A'], ['B'])
        instance.groups.clear()
        self.assert_log('User group', ['A'], [])
        instance.groups.clear()
        self.assert_log('User group', ['A'], [])
        self.assertFalse(hasattr(instance, '_operate_log_m2m_snapshots'))

    def test_group_scalar_audit_fields_are_not_filtered(self):
        instance, _ = self.prepare(Group, 'users', [], [])
        self.edit(instance, name='renamed', org_id='org-2')
        log = OperateLog.objects.get()
        before, after = DBStore.convert_diff_to_before_after(log.diff)
        self.assertEqual(before['Name'], 'resource')
        self.assertEqual(after['Name'], 'renamed')
        self.assertEqual(before['Organization'], 'org-1')
        self.assertEqual(after['Organization'], 'org-2')
        self.assertEqual(log.resource_type, 'User group')

    def test_same_organization_type_change_is_not_an_update(self):
        for model in (Group, AssetPermission, CommandACL):
            with self.subTest(model=model.__name__):
                self.enabled = False
                org_id = str(uuid.uuid4())
                instance = model.objects.create(name='unchanged', org_id=org_id)
                instance.refresh_from_db()
                self.assertIsInstance(instance.org_id, str)
                self.reset_logs()
                self.enabled = True
                self.edit(instance, name='unchanged')
                self.assertIsInstance(instance.org_id, uuid.UUID)
                self.assertEqual(str(instance.org_id), org_id)
                self.assertEqual(OperateLog.objects.count(), 0)

    def test_relation_replacement_omits_unchanged_organization(self):
        paths = [(Group, 'users', 'User'), (AssetPermission, 'users', 'User'),
                 (AssetPermission, 'user_groups', 'User group'),
                 (AssetPermission, 'assets', 'Asset'), (AssetPermission, 'nodes', 'Node'),
                 (CommandACL, 'command_groups', 'Command group')]
        for model, field, label in paths:
            with self.subTest(model=model.__name__, field=field):
                instance, members = self.prepare(model, field, ['A'], ['B'])
                self.enabled = False
                org_id = str(uuid.uuid4())
                instance.org_id = org_id
                instance.save()
                instance.refresh_from_db()
                self.reset_logs()
                self.enabled = True
                self.edit(instance, **{field: [members['B'].pk]})
                before, after = self.assert_log(label, ['A'], ['B'], str(model._meta.verbose_name))
                self.assertNotIn('Organization', before)
                self.assertNotIn('Organization', after)
                self.assertEqual(list(getattr(instance, field).values_list('name', flat=True)), ['B'])
                instance.refresh_from_db()
                self.assertEqual(instance.org_id, org_id)

    def test_name_comment_and_real_organization_changes_are_preserved(self):
        self.enabled = False
        old_org, new_org = str(uuid.uuid4()), str(uuid.uuid4())
        instance = Group.objects.create(name='old', comment='before', org_id=old_org)
        instance.refresh_from_db()
        self.reset_logs()
        self.enabled = True
        self.edit(instance, name='new', comment='after')
        before, after = DBStore.convert_diff_to_before_after(OperateLog.objects.get().diff)
        self.assertEqual(before, {'Name': 'old', 'comment': 'before'})
        self.assertEqual(after, {'Name': 'new', 'comment': 'after'})
        self.reset_logs()
        instance.refresh_from_db()
        self.edit(instance, org_id=new_org)
        before, after = DBStore.convert_diff_to_before_after(OperateLog.objects.get().diff)
        self.assertEqual(before, {'Organization': old_org})
        self.assertEqual(after, {'Organization': new_org})
        instance.refresh_from_db()
        self.assertEqual(instance.org_id, new_org)

    def test_snapshots_keep_organization_and_other_field_types(self):
        org_id = uuid.uuid4()
        snapshot = utils['model_to_dict_for_operate_log'](Group(org_id=org_id, name='new'))
        self.assertEqual(snapshot['Organization'], {'name': 'org_id', 'value': str(org_id)})
        instance = FieldValues(reference=org_id, kind='test', count=0, enabled=False,
                               payload={'key': 1}, items=['A'], timestamp=datetime(2026, 11, 10, 12))
        snapshot = utils['model_to_dict_for_operate_log'](instance)
        self.assertIsInstance(instance.reference, uuid.UUID)
        self.assertIs(snapshot['id']['value'], instance.pk)
        self.assertEqual(snapshot['Reference']['value'], str(org_id))
        self.assertIsInstance(snapshot['Count']['value'], int)
        self.assertIs(snapshot['Enabled']['value'], False)
        self.assertEqual(snapshot['Payload']['value'], {'key': 1})
        self.assertIsNot(snapshot['Payload']['value'], instance.payload)
        self.assertEqual(snapshot['Items']['value'], ['A'])
        self.assertIsNot(snapshot['Items']['value'], instance.items)
        self.assertEqual(snapshot['Kind']['value'], 'Test')
        self.assertEqual(snapshot['Timestamp']['value'], '2026-11-10 12:00:00')

    def test_actual_organization_changes_are_logged_for_all_org_models(self):
        for model in (Group, AssetPermission, CommandACL):
            with self.subTest(model=model.__name__):
                self.enabled = False
                old_org, new_org = str(uuid.uuid4()), str(uuid.uuid4())
                instance = model.objects.create(name='moved', org_id=old_org)
                instance.refresh_from_db()
                self.reset_logs()
                self.enabled = True
                self.edit(instance, org_id=new_org)
                before, after = DBStore.convert_diff_to_before_after(OperateLog.objects.get().diff)
                self.assertEqual(before, {'Organization': old_org})
                self.assertEqual(after, {'Organization': new_org})
                instance.refresh_from_db()
                self.assertEqual(instance.org_id, new_org)

    def test_group_creation_keeps_organization(self):
        self.enabled = True
        org_id = uuid.uuid4()
        Group.objects.create(name='created', org_id=str(org_id))
        log = OperateLog.objects.get()
        self.assertEqual(log.action, 'create')
        _, after = DBStore.convert_diff_to_before_after(log.diff)
        self.assertEqual(after['Organization'], str(org_id))

    def test_group_deletion_keeps_organization(self):
        self.enabled = False
        org_id = uuid.uuid4()
        instance = Group.objects.create(name='deleted', org_id=str(org_id))
        instance.refresh_from_db()
        self.reset_logs()
        self.enabled = True
        instance.delete()
        log = OperateLog.objects.get()
        self.assertEqual(log.action, 'delete')
        before, _ = DBStore.convert_diff_to_before_after(log.diff)
        self.assertEqual(before['Organization'], str(org_id))

    def test_merge_contract_database_and_es(self):
        sequences = [
            [({'Name': 'A'}, {'Name': 'B'})],
            [({'Name': 'A'}, {'Name': 'B'}), ({'Name': 'B'}, {'Name': 'C'})],
            [({'Name': 'A'}, {'Name': 'B'}), ({'User': ''}, {'User': 'U'})],
            [({'User': 'A'}, {'User': 'B'}), ({'User': 'B'}, {'User': ''})],
            [({'User': ''}, {'User': 'B'}), ({'User': 'B'}, {'User': ''})],
            [({'Name': 'A'}, {'Name': 'B'}), ({'Name': 'B'}, {'Name': 'A'})],
        ]
        for sequence in sequences:
            with self.subTest(sequence=sequence):
                self.reset_logs()
                log_id = uuid.uuid4()
                es = object.__new__(ESStore)
                es.es = Mock()
                es.index, es.doc_type = 'test', '_doc'
                document = {'es_id': 'test', 'before': {}, 'after': {}}
                es.get = lambda *a: copy.deepcopy(document)
                expected_before, expected_after = {}, {}
                for before, after in sequence:
                    original = copy.deepcopy((before, after))
                    for key, value in before.items():
                        expected_before.setdefault(key, value)
                    expected_after.update(after)
                    kwargs = dict(id=log_id, resource='resource', resource_type='User',
                                  before=copy.deepcopy(before), after=copy.deepcopy(after))
                    DBStore({}).save(**kwargs)
                    es.save(id=log_id, before=copy.deepcopy(before), after=copy.deepcopy(after))
                    document.update(es.es.update.call_args.kwargs['body']['doc'])
                    self.assertEqual(original, (before, after))
                self.assertEqual(DBStore.convert_diff_to_before_after(OperateLog.objects.get().diff),
                                 (expected_before, expected_after))
                self.assertEqual(document['before'], expected_before)
                self.assertEqual(document['after'], expected_after)

    def test_distinct_log_ids_remain_independent(self):
        for before, after in [('A', 'B'), ('B', 'C')]:
            DBStore({}).save(id=uuid.uuid4(), resource='resource', resource_type='User',
                            before={'Name': before}, after={'Name': after})
        self.assertEqual(OperateLog.objects.count(), 2)
        self.assertEqual([DBStore.convert_diff_to_before_after(log.diff) for log in OperateLog.objects.all()],
                         [({'Name': 'A'}, {'Name': 'B'}), ({'Name': 'B'}, {'Name': 'C'})])


if __name__ == '__main__':
    unittest.main()
