from datetime import datetime

from django.db import models
# Create your models here.

class RecentScansDB(models.Model):
    ANALYZER = models.CharField(max_length=50, default='')
    SCAN_TYPE = models.CharField(max_length=10, default='')
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=260, default='')
    PACKAGE_NAME = models.CharField(max_length=260, default='')
    VERSION_NAME = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='')
    TIMESTAMP = models.DateTimeField(default=datetime.now)


class StaticAnalyzerAndroid(models.Model):
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=255, default='')
    APP_TYPE = models.CharField(max_length=20, default='')
    SIZE = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='')
    PACKAGE_NAME = models.TextField(default='')
    MAIN_ACTIVITY = models.TextField(default='')
    EXPORTED_ACTIVITIES = models.TextField(default='')
    BROWSABLE_ACTIVITIES = models.TextField(default={})
    ACTIVITIES = models.TextField(default=[])
    RECEIVERS = models.TextField(default=[])
    PROVIDERS = models.TextField(default=[])
    SERVICES = models.TextField(default=[])
    LIBRARIES = models.TextField(default=[])
    TARGET_SDK = models.CharField(max_length=50, default='')
    MAX_SDK = models.CharField(max_length=50, default='')
    MIN_SDK = models.CharField(max_length=50, default='')
    VERSION_NAME = models.CharField(max_length=100, default='')
    VERSION_CODE = models.CharField(max_length=50, default='')
    PERMISSIONS = models.TextField(default={})
    MANIFEST_ANALYSIS = models.TextField(default=[])
    CODE_ANALYSIS = models.TextField(default={})
    EMAILS = models.TextField(default=[])
    URLS = models.TextField(default=[])
    EXPORTED_COUNT = models.TextField(default={})
    NETWORK_SECURITY = models.TextField(default=[])
    FLOW_REPORT = models.TextField(default=[])
    DYNAMIC_REPORT = models.TextField(default={})

class JavaResource(models.Model):
    ANALYZER = models.CharField(max_length=50, default='')
    SCAN_TYPE = models.CharField(max_length=10, default='')
    FILE_NAME = models.CharField(max_length=260, default='')
    MD5 = models.CharField(max_length=32, default='')
    TIMESTAMP = models.DateTimeField(default=datetime.now)
    ANALYSIS_RESULT = models.TextField(default=[])