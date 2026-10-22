"""VCTK_S HTTP detached-signature verification client."""
import json
import re
import threading
import time
from http.client import HTTPException

from django.utils.translation import gettext_lazy as _

from .fisherman import (
    MAX_RESPONSE, FishermanClient, SVSError, create_tls_context, decode_base64, parse_service_url,
)


# A P7 proof may include its certificate chain, unlike a raw SM2/RSA signature.
MAX_P7_SIZE = 32768
MAX_MESSAGE_SIZE = 4096


class VCTKSClient(FishermanClient):
    """Reuse bounded DNS/TLS transport with the VCTK_S HTTP wire protocol."""

    def __init__(self, url, *, tls_verify='system', tls_ca_cert='', connect_timeout=3, read_timeout=5):
        self.scheme, self.host, self.port = parse_service_url(url)
        if any(type(value) is not int or not 1 <= value <= limit
               for value, limit in ((connect_timeout, 10), (read_timeout, 20))):
            raise SVSError(_('Invalid certificate service connection parameters'))
        self.tls_context = create_tls_context(self.scheme, tls_verify, tls_ca_cert)
        self.connect_timeout, self.read_timeout = connect_timeout, read_timeout

    @staticmethod
    def _decode_response(data, endpoint):
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result

        try:
            result = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
            if (type(result) is not dict or set(result) != {'error', 'value'}
                    or type(result['error']) not in (int, str)
                    or type(result['value']) is not str):
                raise ValueError
            if result['error'] not in (0, '0'):
                raise ValueError
            value = result['value']
            # A native error can also use error=0 with a failure description.
            # Verification succeeds only with the documented empty result.
            if endpoint == 'JITGetVersion':
                # The manual specifies a version string, without limiting
                # product/platform prefixes to a particular version grammar.
                if (not 1 <= len(value) <= 128 or not value.isascii() or not value.isprintable()
                        or not re.search(r'[0-9]+\.[0-9]+', value)):
                    raise ValueError
            elif endpoint != 'JITGVerifyDetachedSignStr' or value != '':
                raise ValueError
            return value
        except (ValueError, UnicodeError, RecursionError):
            raise SVSError(_('VCTK_S rejected the operation or returned an invalid response.')) from None

    def _request(self, endpoint, params=()):
        parameter_counts = {'JITGetVersion': 0, 'JITGVerifyDetachedSignStr': 2}
        if parameter_counts.get(endpoint) != len(params):
            raise SVSError(_('Invalid VCTK_S operation'))
        body = json.dumps({
            'name': endpoint, **{f'p{i}': value for i, value in enumerate(params, 1)},
        }, ensure_ascii=True).encode('utf-8')
        if len(body) > MAX_RESPONSE:
            raise SVSError(_('Certificate service request is too large'))
        connection = timer = None
        try:
            connection = self._connect()
            sock = connection.sock
            sock.settimeout(self.read_timeout)
            deadline = time.monotonic() + self.read_timeout
            timer = threading.Timer(self.read_timeout, self._abort_response, args=(sock,))
            timer.daemon = True
            timer.start()
            connection.request('POST', '/', body=body, headers={
                'Content-Type': 'text/plain;charset=UTF-8',
                'Accept': 'application/json', 'Connection': 'close',
            })
            with connection.getresponse() as response:
                if response.status != 200 or response.getheader('Content-Encoding', 'identity') != 'identity':
                    raise SVSError(_('Certificate service returned an unexpected HTTP response'))
                data = response.read(MAX_RESPONSE + 1)
                if (len(data) > MAX_RESPONSE or response.length not in (None, 0)
                        or time.monotonic() >= deadline):
                    raise SVSError(_('Invalid or timed out certificate service response'))
            return self._decode_response(data, endpoint)
        except (OSError, HTTPException):
            raise SVSError(_('Certificate service connection failed or timed out')) from None
        finally:
            if timer is not None:
                timer.cancel()
            if connection is not None:
                try:
                    connection.close()
                except (OSError, HTTPException):
                    raise SVSError(_('Certificate service connection failed or timed out')) from None

    def get_version(self):
        """Check the HTTP interface; this does not establish proof verification."""
        return self._request('JITGetVersion')

    def verify_signed_data(self, message, signature):
        """Send P7 Base64 unchanged and the original challenge as plain text."""
        if isinstance(message, bytes):
            try:
                message = message.decode('ascii')
            except UnicodeError:
                raise SVSError(_('Invalid challenge')) from None
        if (not isinstance(message, str) or not 1 <= len(message) <= MAX_MESSAGE_SIZE
                or not message.isascii() or '\0' in message):
            raise SVSError(_('Invalid challenge'))
        decode_base64(signature, MAX_P7_SIZE)
        self._request('JITGVerifyDetachedSignStr', (signature, message))
