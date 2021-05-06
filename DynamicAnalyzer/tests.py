
from django.test import TestCase
from django.utils import timezone
from DynamicAnalyzer.tools.webproxy import start_proxy

class QuestionModelTests(TestCase):

    def test_flow(self):
        """ 
        was_published_recently() returns False for questions whose pub_date
        is in the future.
        """
        start_proxy()