"""Helpers."""
import functools

from django.conf import settings

ALLOW_METHODS = ['GET', 'POST', 'PUT', 'DELETE',
                 'PATCH', 'OPTIONS', 'HEAD', 'TRACE']


class FileType(object):

    def __init__(self, file_obj):
        self.file_type = file_obj.content_type
        self.file_name_lower = file_obj.name.lower()
        self.zip = self.is_zip_magic(file_obj)

    def is_allow_file(self):
        """
        Is File Allowed.

        return bool
        """
        if self.zip and (
            self.is_apk()
                or self.is_zip()):
            return True
        return False

    def is_zip_magic(self, file_obj):
        magic = file_obj.read(4)
        file_obj.seek(0, 0)
        # ZIP magic PK.. no support for spanned and empty arch
        return bool(magic == b'\x50\x4B\x03\x04')

    def is_apk(self):
        return (self.file_type in settings.APK_MIME
                and self.file_name_lower.endswith('.apk'))

    def is_zip(self):
        return (self.file_type in settings.ZIP_MIME
                and self.file_name_lower.endswith('.zip'))

    
  