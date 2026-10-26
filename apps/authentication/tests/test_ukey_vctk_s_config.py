"""VCTK_S configuration must preserve the existing JIT Key user/SN flow."""
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from django.test import SimpleTestCase, override_settings
from rest_framework.exceptions import ValidationError

from authentication.backends.ukey.configuration import REVISION, SECRET_FIELDS
from authentication.backends.ukey.exceptions import UKeyAuthError
from authentication.backends.ukey.providers import get_provider
from authentication.backends.ukey.sdk import UKeySDKConfig
from settings.serializers.auth.ukey import UKeySettingSerializer, UKeyTestingSerializer


ROOT = Path(__file__).resolve().parents[3]


def snapshot(**overrides):
    return {
        'AUTH_UKEY': True,
        'AUTH_UKEY_VENDOR': 'ji_da',
        'AUTH_UKEY_CA_PROVIDER': 'vctk_s',
        REVISION: 'test-revision',
        'AUTH_UKEY_CHALLENGE_TTL': 300,
        'AUTH_UKEY_ENROLL_ENABLED': True,
        'AUTH_UKEY_ENROLL_VALIDITY_DAYS': 365,
        'AUTH_UKEY_DEFAULT_PIN': '123456',
        'AUTH_UKEY_CA_CERT_CONTENT': '',
        'AUTH_UKEY_VCTK_S_SVS_URL': 'http://192.0.2.1:8000',
        'AUTH_UKEY_VCTK_S_ISSUING_CA': 'saved-issuing-ca',
        'AUTH_UKEY_VCTK_S_TLS_VERIFY': 'system',
        'AUTH_UKEY_VCTK_S_TLS_CA_CERT': 'saved-https-ca',
        'AUTH_UKEY_VCTK_S_USERNAME': 'business-user',
        'AUTH_UKEY_VCTK_S_PASSWORD': 'saved-password',
        **overrides,
    }


@override_settings(PROJECT_DIR=str(ROOT), DEBUG_DEV=False)
class SDKCompatibilityTests(SimpleTestCase):
    def setUp(self):
        self.reverse = patch(
            'authentication.backends.ukey.sdk.reverse',
            side_effect=lambda name: '/api/' + name.rsplit(':', 1)[-1] + '/',
        )
        self.reverse.start()
        self.addCleanup(self.reverse.stop)

    def test_reuses_original_jida_script_detection_pin_and_submit(self):
        builtin = UKeySDKConfig(snapshot(AUTH_UKEY_CA_PROVIDER='builtin'))
        remote = UKeySDKConfig(snapshot())
        self.assertEqual(builtin.load_sdk_script_content(), remote.load_sdk_script_content())
        builtin_config = builtin.get_sdk_config(include_admin_pin=True)
        remote_config = remote.get_sdk_config(include_admin_pin=True)
        for section in ('sdk', 'info', 'operations'):
            self.assertEqual(builtin_config[section], remote_config[section])
        expected_login = deepcopy(builtin_config['login'])
        sign = next(step for step in expected_login['steps'] if step['name'] == 'signChallenge')
        sign['call'] = 'UKey_P7SignAttach'
        submit = next(step for step in expected_login['steps'] if step.get('type') == 'submit')
        submit['fields']['challenge_id'] = '{{ challenge.id }}'
        self.assertEqual(expected_login, remote_config['login'])
        self.assertEqual(remote_config['config']['pin'], builtin_config['config']['pin'])
        self.assertFalse(remote_config['config']['enroll']['enabled'])
        self.assertTrue(builtin_config['config']['enroll']['enabled'])
        self.assertTrue(remote_config['config']['capabilities']['uses_one_time_challenge'])
        self.assertFalse(builtin_config['config']['capabilities']['uses_one_time_challenge'])
        self.assertNotIn('saved-password', repr(remote_config))
        self.assertNotIn('business-user', repr(remote_config))

    def test_provider_override_does_not_mutate_cached_builtin_config(self):
        remote = UKeySDKConfig(snapshot())
        remote.get_sdk_config()
        builtin = UKeySDKConfig(snapshot(AUTH_UKEY_CA_PROVIDER='builtin'))
        sign = next(step for step in builtin.get_sdk_config()['login']['steps']
                    if step['name'] == 'signChallenge')
        self.assertEqual(sign['call'], 'UKey_SignData')

    def test_default_pin_is_admin_only(self):
        config = UKeySDKConfig(snapshot())
        self.assertNotIn('pin', config.get_sdk_config()['config'])
        self.assertEqual(config.get_sdk_config(include_admin_pin=True)['config']['pin']['default'], '123456')

    def test_rsa_ca_key_sizes_select_sha256_without_changing_displayed_algorithm(self):
        for algorithm in ('RSA-1024', 'RSA-2048', 'RSA-3072', 'RSA-4096', 'SM2'):
            with self.subTest(algorithm=algorithm), patch(
                'authentication.backends.ukey.providers.vctk_s.detect_cert_algorithm', return_value=algorithm,
            ):
                config = UKeySDKConfig(snapshot()).get_sdk_config()['config']
                self.assertEqual(config['asym_alg_name'], algorithm)
                self.assertEqual(config['digestAlg'], 1 if algorithm == 'SM2' else 4)

    def test_certificate_selection_and_identity_remain_user_sn(self):
        provider = get_provider(snapshot())
        self.assertEqual(provider.binding_mode, 'user_sn')
        self.assertFalse(provider.requires_certificate_selection)
        self.assertFalse(provider.supports_enrollment)
        self.assertTrue(provider.expose_default_pin)
        with self.assertRaises(UKeyAuthError):
            get_provider(snapshot(AUTH_UKEY_VENDOR='long_mai'))

    def test_longmai_provider_and_sdk_profile_still_work(self):
        config = UKeySDKConfig(snapshot(AUTH_UKEY_VENDOR='long_mai', AUTH_UKEY_CA_PROVIDER='xjca'))
        result = config.get_sdk_config()
        self.assertEqual(result['config']['capabilities']['binding_mode'], 'certificate')
        self.assertEqual(config.provider.sdk_profile, 'sdk_config_xjca.yaml')
        constructor = result['sdk']['create']['constructor'].encode()
        self.assertTrue(b'function ' + constructor in config.load_sdk_script_content())
        self.assertNotIn('UKey_P7SignDetach', repr(result['login']))


class SettingsTests(SimpleTestCase):
    def test_public_settings_expose_status_but_not_uploaded_certificates(self):
        result = UKeySettingSerializer(instance=snapshot()).data
        self.assertTrue(result['AUTH_UKEY_VCTK_S_ISSUING_CA_CONFIGURED'])
        for key in ('AUTH_UKEY_VCTK_S_ISSUING_CA', 'AUTH_UKEY_VCTK_S_TLS_CA_CERT',
                    'AUTH_UKEY_VCTK_S_PASSWORD'):
            self.assertNotIn(key, result)
            self.assertIn(key, SECRET_FIELDS)
        provider = next(p for p in result['AUTH_UKEY_CA_PROVIDERS'] if p['id'] == 'vctk_s')
        self.assertEqual(provider['supported_vendors'], ['ji_da'])
        self.assertEqual(provider['binding_mode'], 'user_sn')
        self.assertEqual(set(provider['fields']), {
            'AUTH_UKEY_VCTK_S_SVS_URL', 'AUTH_UKEY_VCTK_S_TLS_VERIFY',
            'AUTH_UKEY_VCTK_S_TLS_CA_CERT', 'AUTH_UKEY_VCTK_S_ISSUING_CA',
            'AUTH_UKEY_VCTK_S_USERNAME', 'AUTH_UKEY_VCTK_S_PASSWORD',
        })
        self.assertEqual(set(provider['connection_fields']), set(provider['fields']) - {
            'AUTH_UKEY_VCTK_S_ISSUING_CA',
        })

    def test_blank_password_keeps_saved_secret_and_empty_username_disables_authorization(self):
        with patch('authentication.backends.ukey.providers.vctk_s.VCTKSVerifier') as verifier:
            serializer = UKeySettingSerializer(
                data={'AUTH_UKEY_VCTK_S_USERNAME': '', 'AUTH_UKEY_VCTK_S_PASSWORD': ''},
                partial=True, context={'snapshot': snapshot()},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            self.assertEqual(verifier.call_args.kwargs['username'], '')
            self.assertEqual(verifier.call_args.kwargs['password'], 'saved-password')
        serializer = UKeyTestingSerializer(
            data={'AUTH_UKEY_CA_PROVIDER': 'vctk_s', 'AUTH_UKEY_VCTK_S_PASSWORD': ''},
            context={'snapshot': snapshot()},
        )
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertNotIn('AUTH_UKEY_VCTK_S_PASSWORD', serializer.validated_data)

    def test_blank_upload_keeps_saved_ca_during_validation(self):
        state = snapshot()
        with patch('authentication.backends.ukey.providers.vctk_s.VCTKSVerifier') as verifier:
            serializer = UKeySettingSerializer(
                data={'AUTH_UKEY_VCTK_S_ISSUING_CA': '', 'AUTH_UKEY_VCTK_S_TLS_CA_CERT': ''},
                partial=True, context={'snapshot': state},
            )
            self.assertTrue(serializer.is_valid(), serializer.errors)
            self.assertEqual(verifier.call_args.kwargs['issuing_ca'], 'saved-issuing-ca')
            self.assertEqual(verifier.call_args.kwargs['tls_ca_cert'], 'saved-https-ca')

    def test_missing_required_settings_and_incompatible_vendor(self):
        for missing in ('AUTH_UKEY_VCTK_S_SVS_URL', 'AUTH_UKEY_VCTK_S_ISSUING_CA'):
            with self.subTest(missing=missing), self.assertRaises(ValidationError) as error:
                get_provider(snapshot(**{missing: ''})).validate_config()
            self.assertIn(missing, error.exception.detail)
        serializer = UKeySettingSerializer(
            data={'AUTH_UKEY_VENDOR': 'long_mai'}, partial=True, context={'snapshot': snapshot()},
        )
        self.assertFalse(serializer.is_valid())
        self.assertIn('AUTH_UKEY_VENDOR', serializer.errors)

    def test_custom_https_requires_ca_but_http_and_system_do_not(self):
        with self.assertRaises(ValidationError) as error:
            get_provider(snapshot(
                AUTH_UKEY_VCTK_S_SVS_URL='https://192.0.2.1',
                AUTH_UKEY_VCTK_S_TLS_VERIFY='custom', AUTH_UKEY_VCTK_S_TLS_CA_CERT='',
            )).validate_config()
        self.assertIn('AUTH_UKEY_VCTK_S_TLS_CA_CERT', error.exception.detail)
        with patch('authentication.backends.ukey.providers.vctk_s.VCTKSVerifier'):
            for url, trust in (('http://192.0.2.1', 'custom'), ('https://192.0.2.1', 'system')):
                get_provider(snapshot(
                    AUTH_UKEY_VCTK_S_SVS_URL=url, AUTH_UKEY_VCTK_S_TLS_VERIFY=trust,
                    AUTH_UKEY_VCTK_S_TLS_CA_CERT='',
                )).validate_config()

    def test_disabling_remains_possible_with_unusable_service_and_ca(self):
        get_provider(snapshot(
            AUTH_UKEY=False, AUTH_UKEY_VCTK_S_SVS_URL='', AUTH_UKEY_VCTK_S_ISSUING_CA='',
        )).validate_config()

    def test_connection_test_only_accepts_service_settings(self):
        context = {'snapshot': snapshot()}
        serializer = UKeyTestingSerializer(data={
            'AUTH_UKEY_VENDOR': 'ji_da', 'AUTH_UKEY_CA_PROVIDER': 'vctk_s',
            'AUTH_UKEY_VCTK_S_TLS_CA_CERT': '',
        }, context=context)
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertNotIn('AUTH_UKEY_VCTK_S_TLS_CA_CERT', serializer.validated_data)
        serializer = UKeyTestingSerializer(data={
            'AUTH_UKEY_CA_PROVIDER': 'vctk_s', 'AUTH_UKEY_VCTK_S_ISSUING_CA': 'not-a-connection-field',
        }, context=context)
        self.assertFalse(serializer.is_valid())
        self.assertIn('AUTH_UKEY_VCTK_S_ISSUING_CA', serializer.errors)
