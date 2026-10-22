"""VCTK_S wire protocol and transport failures, without a live service."""
import base64
import json
import socket
import ssl
import unittest
from http.client import BadStatusLine
from unittest.mock import MagicMock, patch

from authentication.backends.ukey.clients.fisherman import MAX_RESPONSE, SVSError
from authentication.backends.ukey.clients.vctk_s import MAX_MESSAGE_SIZE, MAX_P7_SIZE, VCTKSClient


CLIENT_MODULE = 'authentication.backends.ukey.clients.vctk_s'
TRANSPORT_MODULE = 'authentication.backends.ukey.clients.fisherman'
URL = 'http://192.168.10.5:8000'
CHALLENGE = '0123456789abcdef' * 2
SIGNATURE = base64.b64encode(b'P7 proof bytes\xfb\xff').decode('ascii')


def http_response(data=b'{"error":"0","value":""}'):
    response = MagicMock()
    response.__enter__.return_value = response
    response.status, response.length = 200, 0
    response.getheader.return_value = 'identity'
    response.read.return_value = data
    return response


class VCTKSProtocolTests(unittest.TestCase):
    def test_exact_zero_and_void_result(self):
        for code in (0, '0'):
            with self.subTest(code=code):
                self.assertEqual(VCTKSClient._decode_response(
                    json.dumps({'error': code, 'value': ''}).encode(), 'JITGVerifyDetachedSignStr',
                ), '')

    def test_ambiguous_success_is_rejected(self):
        for code in (False, True, None, 0.0, '00', ' 0', '+0', '', 1, '3758096470'):
            with self.subTest(code=code), self.assertRaises(SVSError):
                VCTKSClient._decode_response(
                    json.dumps({'error': code, 'value': ''}).encode(), 'JITGVerifyDetachedSignStr',
                )
        for value in ('init faild', 'OK', 'true', False, None, 0, {}):
            with self.subTest(value=value), self.assertRaises(SVSError):
                VCTKSClient._decode_response(
                    json.dumps({'error': 0, 'value': value}).encode(), 'JITGVerifyDetachedSignStr',
                )

    def test_malformed_duplicate_extra_or_missing_fields_are_rejected(self):
        for body in (
            b'{}', b'[]', b'null', b'{"error":0}', b'\xff', b'{"error":0,"value":""}junk',
            b'{"error":1,"error":0,"value":""}', b'{"error":0,"value":"","value":""}',
            b'{"error":0,"value":"","unexpected":true}',
        ):
            with self.subTest(body=body), self.assertRaises(SVSError):
                VCTKSClient._decode_response(body, 'JITGVerifyDetachedSignStr')

    def test_version_check_requires_a_version_result(self):
        for version in ('2.2.7.1', '1.0', 'v1.2.3', 'VCTK_S V4.0', 'V2.2.7.1 (Linux)'):
            with self.subTest(version=version):
                self.assertEqual(VCTKSClient._decode_response(
                    json.dumps({'error': '0', 'value': version}).encode(), 'JITGetVersion',
                ), version)
        for value in ('getversion faild', '', 'success', '<html>', '1.0\n', '1' * 129):
            with self.subTest(value=value), self.assertRaises(SVSError):
                VCTKSClient._decode_response(
                    json.dumps({'error': 0, 'value': value}).encode(), 'JITGetVersion',
                )

    def test_version_query_uses_only_the_version_operation(self):
        client = VCTKSClient(URL)
        connection = MagicMock()
        connection.getresponse.return_value = http_response(b'{"error":0,"value":"2.2.7.1"}')
        with patch.object(client, '_connect', return_value=connection):
            self.assertEqual(client.get_version(), '2.2.7.1')
        self.assertEqual(connection.request.call_count, 1)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ('POST', '/'))
        self.assertEqual(json.loads(kwargs['body']), {'name': 'JITGetVersion'})
        connection.close.assert_called_once()

    def test_verification_sends_one_request_with_original_p7_and_challenge(self):
        for message in (CHALLENGE, CHALLENGE.encode('ascii')):
            client = VCTKSClient(URL)
            connection = MagicMock()
            connection.getresponse.return_value = http_response()
            with self.subTest(message_type=type(message).__name__), patch.object(
                client, '_connect', return_value=connection,
            ):
                client.verify_signed_data(message, SIGNATURE)
            self.assertEqual(connection.request.call_count, 1)
            args, kwargs = connection.request.call_args
            self.assertEqual(args, ('POST', '/'))
            self.assertEqual(kwargs['headers'], {
                'Content-Type': 'text/plain;charset=UTF-8',
                'Accept': 'application/json', 'Connection': 'close',
            })
            self.assertEqual(json.loads(kwargs['body']), {
                'name': 'JITGVerifyDetachedSignStr', 'p1': SIGNATURE, 'p2': CHALLENGE,
            })
            connection.close.assert_called_once()

    def test_maximum_p7_fits_request_and_is_preserved(self):
        client = VCTKSClient(URL)
        signature = base64.b64encode(b'x' * MAX_P7_SIZE).decode('ascii')
        connection = MagicMock()
        connection.getresponse.return_value = http_response()
        with patch.object(client, '_connect', return_value=connection):
            client.verify_signed_data(CHALLENGE, signature)
        body = connection.request.call_args.kwargs['body']
        self.assertLess(len(body), MAX_RESPONSE)
        self.assertEqual(json.loads(body)['p1'], signature)

    def test_invalid_proof_inputs_never_connect(self):
        client = VCTKSClient(URL)
        invalid_pairs = [
            ('', SIGNATURE), (None, SIGNATURE), (False, SIGNATURE),
            ('a' * (MAX_MESSAGE_SIZE + 1), SIGNATURE), ('\0', SIGNATURE),
            (b'\xff', SIGNATURE), ('\u00e9', SIGNATURE),
            (CHALLENGE, ''), (CHALLENGE, None), (CHALLENGE, 'bad base64!'),
            (CHALLENGE, SIGNATURE + '\n'),
            (CHALLENGE, base64.b64encode(b'x' * (MAX_P7_SIZE + 1)).decode('ascii')),
        ]
        for message, signature in invalid_pairs:
            with self.subTest(message_type=type(message).__name__), patch.object(
                client, '_connect',
            ) as connect, self.assertRaises(SVSError):
                client.verify_signed_data(message, signature)
            connect.assert_not_called()

    def test_request_size_and_unavailable_operations_fail_before_connection(self):
        client = VCTKSClient(URL)
        invalid_calls = [
            ('JITGVerifyDetachedSignStr', ('x' * MAX_RESPONSE, CHALLENGE)),
            ('JITGetVersion', ('unexpected',)), ('UnknownOperation', ()),
        ]
        for endpoint, params in invalid_calls:
            with self.subTest(endpoint=endpoint), patch.object(
                client, '_connect',
            ) as connect, self.assertRaises(SVSError):
                client._request(endpoint, params)
            connect.assert_not_called()


class VCTKSTransportTests(unittest.TestCase):
    def test_url_tls_and_timeout_guards(self):
        for url in (
            'http://127.0.0.1', 'http://169.254.169.254', 'https://user:pw@example.com',
            URL + '/api', URL + '?x=1', URL + '#x',
        ):
            with self.subTest(url=url), self.assertRaises(SVSError):
                VCTKSClient(url)
        for kwargs in (
            {'connect_timeout': 0}, {'connect_timeout': 11}, {'read_timeout': 21},
            {'read_timeout': True}, {'tls_verify': 'custom'}, {'tls_verify': 'unknown'},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(SVSError):
                VCTKSClient('https://vctks.example.com', **kwargs)

    def test_https_verification_is_scoped_to_the_client(self):
        verified = VCTKSClient('https://vctks.example.com')
        insecure = VCTKSClient('https://vctks.example.com', tls_verify='insecure')
        self.assertEqual(verified.tls_context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(verified.tls_context.check_hostname)
        self.assertEqual(insecure.tls_context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(insecure.tls_context.check_hostname)
        self.assertIsNone(VCTKSClient(URL).tls_context)
        with patch(CLIENT_MODULE + '.create_tls_context') as create_context:
            custom = VCTKSClient(
                'https://vctks.example.com', tls_verify='custom', tls_ca_cert='CA PEM',
            )
        create_context.assert_called_once_with('https', 'custom', 'CA PEM')
        self.assertIs(custom.tls_context, create_context.return_value)

    def test_http_failures_are_closed_without_retries(self):
        for kind in ('redirect', 'compressed', 'oversized', 'incomplete', 'timeout', 'invalid_headers'):
            client = VCTKSClient(URL)
            connection, response = MagicMock(), http_response()
            connection.getresponse.return_value = response
            if kind == 'redirect':
                response.status = 302
            elif kind == 'compressed':
                response.getheader.return_value = 'gzip'
            elif kind == 'oversized':
                response.read.return_value = b' ' * (MAX_RESPONSE + 1)
            elif kind == 'incomplete':
                response.length = 10
            elif kind == 'invalid_headers':
                connection.getresponse.side_effect = BadStatusLine('sensitive input')
            else:
                response.read.side_effect = TimeoutError('sensitive input')
            with self.subTest(kind=kind), patch.object(
                client, '_connect', return_value=connection,
            ) as connect, self.assertRaises(SVSError) as error:
                client.verify_signed_data(CHALLENGE, SIGNATURE)
            connect.assert_called_once()
            connection.request.assert_called_once()
            connection.close.assert_called_once()
            self.assertNotIn('sensitive input', str(error.exception))

    def test_read_deadline_aborts_the_socket_and_cancels_timer(self):
        client = VCTKSClient(URL, read_timeout=5)
        connection = MagicMock()
        connection.getresponse.return_value = http_response()
        with patch.object(client, '_connect', return_value=connection), patch(
            CLIENT_MODULE + '.threading.Timer',
        ) as timer, patch(CLIENT_MODULE + '.time.monotonic', side_effect=[10, 16]):
            with self.assertRaises(SVSError):
                client.verify_signed_data(CHALLENGE, SIGNATURE)
        timer.assert_called_once_with(5, client._abort_response, args=(connection.sock,))
        timer.return_value.start.assert_called_once()
        timer.return_value.cancel.assert_called_once()
        connection.close.assert_called_once()

    def test_transport_error_does_not_expose_exception_text(self):
        client = VCTKSClient(URL)
        with patch.object(client, '_connect', side_effect=OSError('sensitive input')):
            with self.assertRaises(SVSError) as error:
                client.verify_signed_data(CHALLENGE, SIGNATURE)
        self.assertNotIn('sensitive input', str(error.exception))

    def test_cleanup_error_does_not_expose_exception_text(self):
        client = VCTKSClient(URL)
        connection = MagicMock()
        connection.getresponse.return_value = http_response()
        connection.close.side_effect = OSError('sensitive input')
        with patch.object(client, '_connect', return_value=connection):
            with self.assertRaises(SVSError) as error:
                client.verify_signed_data(CHALLENGE, SIGNATURE)
        self.assertNotIn('sensitive input', str(error.exception))

    def test_https_connects_only_to_resolved_ip_and_keeps_hostname_for_tls(self):
        client = VCTKSClient('https://vctks.example.com:8000')
        client.tls_context = MagicMock()
        with patch.object(client, '_resolve_hosts', return_value=['192.168.10.5']) as resolve, patch(
            TRANSPORT_MODULE + '.socket.socket',
        ) as socket_factory, patch(TRANSPORT_MODULE + '.time.monotonic', return_value=10):
            connection = client._connect()
        resolve.assert_called_once_with(13)
        socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        sock = socket_factory.return_value
        sock.connect.assert_called_once_with(('192.168.10.5', 8000))
        client.tls_context.wrap_socket.assert_called_once_with(sock, server_hostname='vctks.example.com')
        self.assertIs(connection.sock, client.tls_context.wrap_socket.return_value)
        self.assertEqual(connection.auto_open, 0)
        connection.close()

    def test_tls_failure_closes_socket_and_never_creates_a_connection(self):
        client = VCTKSClient('https://vctks.example.com')
        client.tls_context = MagicMock()
        client.tls_context.wrap_socket.side_effect = ssl.SSLCertVerificationError('sensitive input')
        with patch.object(client, '_resolve_hosts', return_value=['192.168.10.5']), patch(
            TRANSPORT_MODULE + '.socket.socket',
        ) as socket_factory, patch(TRANSPORT_MODULE + '.HTTPSConnection') as connection, patch(
            TRANSPORT_MODULE + '.time.monotonic', return_value=10,
        ):
            with self.assertRaises(SVSError) as error:
                client._connect()
        socket_factory.return_value.close.assert_called_once()
        connection.assert_not_called()
        self.assertNotIn('sensitive input', str(error.exception))

    def test_resolution_failure_never_opens_a_socket(self):
        client = VCTKSClient('http://vctks.example.com')
        with patch.object(client, '_resolve_hosts', side_effect=TimeoutError), patch(
            TRANSPORT_MODULE + '.socket.socket',
        ) as socket_factory:
            with self.assertRaises(SVSError):
                client.verify_signed_data(CHALLENGE, SIGNATURE)
        socket_factory.assert_not_called()

    def test_all_resolved_addresses_are_validated_before_connecting(self):
        client = VCTKSClient('http://vctks.example.com')
        records = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.168.10.5', 8000)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('169.254.169.254', 8000)),
        ]
        with patch(TRANSPORT_MODULE + '.socket.getaddrinfo', return_value=records), patch(
            TRANSPORT_MODULE + '.socket.socket',
        ) as socket_factory:
            with self.assertRaises(SVSError):
                client.verify_signed_data(CHALLENGE, SIGNATURE)
        socket_factory.assert_not_called()
