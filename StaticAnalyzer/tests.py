import datetime

from django.test import TestCase
from django.utils import timezone
from StaticAnalyzer.views.flow_analysis import flow_analysis


class QuestionModelTests(TestCase):

    def test_flow(self):
        """
        was_published_recently() returns False for questions whose pub_date
        is in the future.
        """
        flow_analysis('/Users/nine/VSCode/python-project/securityanalyzer/media/upload/764bd7cb9f32c0c042ddbac67d891479',
                        '/Users/nine/VSCode/python-project/securityanalyzer/media/upload/764bd7cb9f32c0c042ddbac67d891479/764bd7cb9f32c0c042ddbac67d891479.apk'
                        ,'/Users/nine/VSCode/python-project/securityanalyzer/StaticAnalyzer/tools',
                        25)