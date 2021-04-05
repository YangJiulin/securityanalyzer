# Generated by Django 3.1.7 on 2021-03-30 13:40

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('StaticAnalyzer', '0003_auto_20210330_1824'),
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
        migrations.RenameModel(
            old_name='JavaSourceAnalyzer',
            new_name='JavaResource',
        ),
        migrations.RemoveField(
            model_name='staticanalyzerandroid',
            name='SCAN_TYPE',
        ),
        migrations.RemoveField(
            model_name='staticanalyzerandroid',
            name='STATIC_REPORT',
        ),
        migrations.RemoveField(
            model_name='staticanalyzerandroid',
            name='TIMESTAMP',
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='ACTIVITIES',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='ANDROID_API',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='APKID',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='APP_TYPE',
            field=models.CharField(default='', max_length=20),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='BINARY_ANALYSIS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='BROWSABLE_ACTIVITIES',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='CERTIFICATE_ANALYSIS',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='CODE_ANALYSIS',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='DOMAINS',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='EMAILS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='EXPORTED_ACTIVITIES',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='EXPORTED_COUNT',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='FILES',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='FILE_ANALYSIS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='FIREBASE_URLS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='ICON_FOUND',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='ICON_HIDDEN',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='LIBRARIES',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='MAIN_ACTIVITY',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='MANIFEST_ANALYSIS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='MAX_SDK',
            field=models.CharField(default='', max_length=50),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='MIN_SDK',
            field=models.CharField(default='', max_length=50),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='NETWORK_SECURITY',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='NIAP_ANALYSIS',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='PERMISSIONS',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='PLAYSTORE_DETAILS',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='PROVIDERS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='RECEIVERS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='SECRETS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='SERVICES',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='SHA1',
            field=models.CharField(default='', max_length=40),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='SHA256',
            field=models.CharField(default='', max_length=64),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='SIZE',
            field=models.CharField(default='', max_length=50),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='STRINGS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='TARGET_SDK',
            field=models.CharField(default='', max_length=50),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='TRACKERS',
            field=models.TextField(default={}),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='URLS',
            field=models.TextField(default=[]),
        ),
        migrations.AddField(
            model_name='staticanalyzerandroid',
            name='VERSION_CODE',
            field=models.CharField(default='', max_length=50),
        ),
        migrations.AlterField(
            model_name='staticanalyzerandroid',
            name='APP_NAME',
            field=models.CharField(default='', max_length=255),
        ),
        migrations.AlterField(
            model_name='staticanalyzerandroid',
            name='PACKAGE_NAME',
            field=models.TextField(default=''),
        ),
        migrations.AlterField(
            model_name='staticanalyzerandroid',
            name='VERSION_NAME',
            field=models.CharField(default='', max_length=100),
        ),
    ]