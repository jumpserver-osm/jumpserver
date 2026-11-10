import uuid

from django.db import models


class UserGroup(models.Model):
    name = models.CharField(max_length=128, verbose_name='Name')
    org_id = models.CharField(max_length=36, default='org-1', verbose_name='Organization')
    comment = models.TextField(default='')
    created_by = models.CharField(max_length=128, default='admin')
    date_created = models.DateTimeField(auto_now_add=True)
    labels = models.JSONField(default=list, blank=True)

    class Meta:
        app_label = 'audit_test_app'
        verbose_name = 'User group'

    def __str__(self):
        return self.name


class User(models.Model):
    name = models.CharField(max_length=128, verbose_name='Name')
    groups = models.ManyToManyField(UserGroup, related_name='users', verbose_name='User group')
    is_service_account = models.BooleanField(default=False)

    class Meta:
        app_label = 'audit_test_app'
        verbose_name = 'User'

    def __str__(self):
        return self.name


class OperateLog(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    org_id = models.CharField(max_length=36, default='org-1')
    resource = models.CharField(max_length=128, default='')
    resource_type = models.CharField(max_length=64, default='')
    user = models.CharField(max_length=128, default='admin')
    action = models.CharField(max_length=16, default='update', choices=[
        ('create', 'Create'), ('delete', 'Delete'), ('update', 'Update'),
    ])
    resource_id = models.CharField(max_length=128, default='')
    remote_addr = models.CharField(max_length=128, default='')
    datetime = models.DateTimeField(auto_now_add=True)
    diff = models.JSONField(default=dict)

    class Meta:
        app_label = 'audit_test_app'


Group = UserGroup


class NamedModel(models.Model):
    name = models.CharField(max_length=128, verbose_name='Name')

    class Meta:
        abstract = True

    def __str__(self):
        return self.name


class Asset(NamedModel):
    class Meta:
        verbose_name = 'Asset'


class Node(NamedModel):
    class Meta:
        verbose_name = 'Node'


class Permission(NamedModel):
    class Meta:
        verbose_name = 'Permissions'


class CommandGroup(NamedModel):
    class Meta:
        verbose_name = 'Command group'


class AssetPermission(NamedModel):
    users = models.ManyToManyField(User, verbose_name='User')
    user_groups = models.ManyToManyField(UserGroup, verbose_name='User group')
    assets = models.ManyToManyField(Asset, verbose_name='Asset')
    nodes = models.ManyToManyField(Node, verbose_name='Node')

    class Meta:
        verbose_name = 'Asset permission'


class Role(NamedModel):
    permissions = models.ManyToManyField(Permission, verbose_name='Permissions')

    class Meta:
        verbose_name = 'Role'


class CommandACL(NamedModel):
    command_groups = models.ManyToManyField(CommandGroup, verbose_name='Command group')
    reviewers = models.ManyToManyField(User, verbose_name='Reviewers')

    class Meta:
        verbose_name = 'Command acl'


class Host(NamedModel):
    nodes = models.ManyToManyField(Node, verbose_name='Nodes')

    class Meta:
        verbose_name = 'Host'


class BackupPlan(NamedModel):
    recipients_one = models.ManyToManyField(User, related_name='backup_one', verbose_name='Recipient one')
    recipients_two = models.ManyToManyField(User, related_name='backup_two', verbose_name='Recipient two')

    class Meta:
        verbose_name = 'Backup plan'
