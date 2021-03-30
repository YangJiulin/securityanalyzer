from datetime import datetime

from django.db import models
from Report.models import AndroidStaticReport
# Create your models here.

class StaticAnalyzerAndroid(models.Model):
    SCAN_TYPE = models.CharField(max_length=10, default='')
    FILE_NAME = models.CharField(max_length=260, default='')
    APP_NAME = models.CharField(max_length=260, default='')
    PACKAGE_NAME = models.CharField(max_length=260, default='')
    VERSION_NAME = models.CharField(max_length=50, default='')
    MD5 = models.CharField(max_length=32, default='')
    TIMESTAMP = models.DateTimeField(default=datetime.now)
    DYNAMIC_REPORT = models.TextField(default={})
    FLOW_REPORT = models.TextField(default=[])
    STATIC_REPORT = models.OneToOneField(AndroidStaticReport,on_delete=models.PROTECT)

class JavaSourceAnalyzer(models.Model):
    ANALYZER = models.CharField(max_length=50, default='')
    SCAN_TYPE = models.CharField(max_length=10, default='')
    FILE_NAME = models.CharField(max_length=260, default='')
    MD5 = models.CharField(max_length=32, default='')
    ANALYSIS_RESULT = models.TextField(default=[])
    TIMESTAMP = models.DateTimeField(default=datetime.now)