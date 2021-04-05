# Generated by Django 3.1.7 on 2021-03-30 02:31

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='RecentScansDB',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ANALYZER', models.CharField(default='', max_length=50)),
                ('SCAN_TYPE', models.CharField(default='', max_length=10)),
                ('FILE_NAME', models.CharField(default='', max_length=260)),
                ('APP_NAME', models.CharField(default='', max_length=260)),
                ('PACKAGE_NAME', models.CharField(default='', max_length=260)),
                ('VERSION_NAME', models.CharField(default='', max_length=50)),
                ('MD5', models.CharField(default='', max_length=32)),
                ('TIMESTAMP', models.DateTimeField(default=datetime.datetime.now)),
            ],
        ),
        migrations.CreateModel(
            name='StaticAnalyzerAndroid',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('FILE_NAME', models.CharField(default='', max_length=260)),
                ('APP_NAME', models.CharField(default='', max_length=255)),
                ('APP_TYPE', models.CharField(default='', max_length=20)),
                ('SIZE', models.CharField(default='', max_length=50)),
                ('MD5', models.CharField(default='', max_length=32)),
                ('SHA1', models.CharField(default='', max_length=40)),
                ('SHA256', models.CharField(default='', max_length=64)),
                ('PACKAGE_NAME', models.TextField(default='')),
                ('MAIN_ACTIVITY', models.TextField(default='')),
                ('EXPORTED_ACTIVITIES', models.TextField(default='')),
                ('BROWSABLE_ACTIVITIES', models.TextField(default={})),
                ('ACTIVITIES', models.TextField(default=[])),
                ('RECEIVERS', models.TextField(default=[])),
                ('PROVIDERS', models.TextField(default=[])),
                ('SERVICES', models.TextField(default=[])),
                ('LIBRARIES', models.TextField(default=[])),
                ('TARGET_SDK', models.CharField(default='', max_length=50)),
                ('MAX_SDK', models.CharField(default='', max_length=50)),
                ('MIN_SDK', models.CharField(default='', max_length=50)),
                ('VERSION_NAME', models.CharField(default='', max_length=100)),
                ('VERSION_CODE', models.CharField(default='', max_length=50)),
                ('ICON_HIDDEN', models.BooleanField(default=False)),
                ('ICON_FOUND', models.BooleanField(default=False)),
                ('PERMISSIONS', models.TextField(default={})),
                ('CERTIFICATE_ANALYSIS', models.TextField(default={})),
                ('MANIFEST_ANALYSIS', models.TextField(default=[])),
                ('BINARY_ANALYSIS', models.TextField(default=[])),
                ('FILE_ANALYSIS', models.TextField(default=[])),
                ('ANDROID_API', models.TextField(default={})),
                ('CODE_ANALYSIS', models.TextField(default={})),
                ('NIAP_ANALYSIS', models.TextField(default={})),
                ('URLS', models.TextField(default=[])),
                ('DOMAINS', models.TextField(default={})),
                ('EMAILS', models.TextField(default=[])),
                ('STRINGS', models.TextField(default=[])),
                ('FIREBASE_URLS', models.TextField(default=[])),
                ('FILES', models.TextField(default=[])),
                ('EXPORTED_COUNT', models.TextField(default={})),
                ('APKID', models.TextField(default={})),
                ('TRACKERS', models.TextField(default={})),
                ('PLAYSTORE_DETAILS', models.TextField(default={})),
                ('NETWORK_SECURITY', models.TextField(default=[])),
                ('SECRETS', models.TextField(default=[])),
            ],
        ),
    ]