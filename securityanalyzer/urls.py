"""securityanalyzer URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.urls.conf import re_path
from Home.views import home
from StaticAnalyzer.views import manifest_view, static_analyzer,view_source
from DynamicAnalyzer.views import dynamic_analyzer as dz
from DynamicAnalyzer.views import (
    operations,
    report,
    tests_common,
    tests_frida,
)
urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'^$', home.index, name='home'),
    re_path(r'^upload/$', home.Upload.as_view),

    # Static Analysis
    # Android
    re_path(r'^static_analyzer/$',static_analyzer.static_analyzer),
    re_path(r'^manifest_view/$', manifest_view.run),
    re_path(r'^view_file/$', view_source.run, name='view_source'),
    # Dynamic Analysis
    re_path(r'^dynamic_analysis/$',
            dz.dynamic_analysis,
            name='dynamic'),
    re_path(r'^android_dynamic/(?P<checksum>[0-9a-f]{32})$',
            dz.dynamic_analyzer,
            name='dynamic_analyzer'),
    re_path(r'^httptools$',
            dz.httptools_start,
            name='httptools'),
    re_path(r'^logcat/$', dz.logcat),


     # Dynamic Tests
    re_path(r'^activity_tester/$', tests_common.activity_tester),
    re_path(r'^download_data/$', tests_common.download_data),
    re_path(r'^collect_logs/$', tests_common.collect_logs),
    # Frida
    re_path(r'^frida_instrument/$', tests_frida.instrument),
    re_path(r'^live_api/$', tests_frida.live_api),
    re_path(r'^frida_logs/$', tests_frida.frida_logs),
    re_path(r'^list_frida_scripts/$', tests_frida.list_frida_scripts),
    re_path(r'^get_script/$', tests_frida.get_script),
]