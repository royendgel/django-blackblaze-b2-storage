from tempfile import TemporaryFile

from io import BytesIO
from django.conf import settings
from django.core.files.storage import Storage
from django.core.files.base import File
from django.utils.deconstruct import deconstructible

from .backblaze_b2 import BackBlazeB2


INTERNAL_SPLIT = ']['


@deconstructible
class B2Storage(Storage):
    def __init__(self):
        kwargs = {
            'key_id': settings.BACKBLAZEB2_APP_KEY_ID,
            'app_key': settings.BACKBLAZEB2_APP_KEY,
            'bucket_name': settings.BACKBLAZEB2_BUCKET_NAME,
            'bucket_id': settings.BACKBLAZEB2_BUCKET_ID,
        }
        if getattr(settings, 'BACKBLAZEB2_AUTHORIZATION_BUFFER', None) is not None:
            kwargs['reauthorization_buffer'] = settings.BACKBLAZEB2_AUTHORIZATION_BUFFER
        if getattr(settings, 'BACKBLAZEB2_USER_AGENT', None) is not None:
            kwargs['user_agent'] = settings.BACKBLAZEB2_USER_AGENT

        self.b2 = BackBlazeB2(**kwargs)

    def _open(self, name, mode='rb'):
        filename, _ = name.split(INTERNAL_SPLIT)
        resp = self.b2.download_file(filename)

        output = BytesIO()
        output.write(resp)
        output.seek(0)
        return File(output, name)

    def _save(self, name, content, max_length=None):
        """
        Save and retrieve the filename.
        If the file exists it will make another version of that file.
        """
        response = self.b2.upload_file(name, content)
        filename, file_id = response['fileName'], response['fileId']
        return f'{filename}{INTERNAL_SPLIT}{file_id}'

    def delete(self, name):
        filename, file_id = name.split(INTERNAL_SPLIT)
        return self.b2.delete_file_version(filename, file_id)

    def exists(self, name):
        return False

    def size(self, name):
        _, file_id = name.split(INTERNAL_SPLIT)
        try:
            info = self.b2.get_file_info(file_id).json()
            return info['contentLength']
        except Exception:
            return None

    def url(self, name):
        filename, _ = name.split(INTERNAL_SPLIT)
        return self.b2.get_file_url(filename)

    def path(self, name):
        # This is needed because Django will throw an exception if it's not
        # overridden by Storage subclasses. We don't need it.
        return name
