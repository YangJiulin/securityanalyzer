from django.test import TestCase

# Create your tests here.
from translate import Translator
translator= Translator(to_lang="chinese")#指定要翻译成的语言
translation = translator.translate("Allows application to send SMS messages. Malicious applications may cost you money by sending messages without your confirmation")
print(translation)