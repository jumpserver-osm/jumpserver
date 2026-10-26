"""Exercise challenge consumption through the authentication backend."""
from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch

from django.core.cache import cache
from django.core.exceptions import PermissionDenied
from django.test import SimpleTestCase, override_settings

from authentication.backends.ukey import backends, challenges
from authentication.backends.ukey.configuration import REVISION
from authentication.backends.ukey.exceptions import UKeyAuthError, UKeyServiceError
from authentication.tests.test_ukey_vctk_s_challenges import request
from authentication.tests.test_ukey_vctk_s_config import snapshot


@override_settings(CACHES={'default': {'BACKEND': 'django.core.cache.backends.locmem.LocMemCache'}})
class VCTKSLoginTests(SimpleTestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        self.state = snapshot()
        self.request = request()
        self.user = SimpleNamespace(username='user', ukey_sn='serial')
        self.backend = backends.UKeyBackend()
        patches = (
            patch.object(backends, 'get_snapshot', side_effect=lambda: self.state),
            patch.object(challenges, 'get_snapshot', side_effect=lambda: self.state),
            patch.object(backends, 'locked_snapshot', side_effect=self.locked),
            patch.object(self.backend, '_check_user_and_ukey_sn', return_value=self.user),
            patch.object(self.backend, 'user_can_authenticate', return_value=True),
            patch('authentication.backends.ukey.providers.vctk_s.VCTKSCAProvider.generate_challenge',
                  return_value='ab' * 32),
        )
        for mocked in patches:
            mocked.start()
            self.addCleanup(mocked.stop)
        verifier = patch('authentication.backends.ukey.providers.vctk_s.VCTKSCAProvider.verify_proof')
        self.verify = verifier.start()
        self.addCleanup(verifier.stop)
        self.issued = challenges.issue(self.request, 'login')
        self.proof = {
            'cert': 'certificate', 'signature': 'attached-signature', 'ukey_sn': 'serial',
            'challenge_id': self.issued['id'], 'challenge': 'client-supplied-untrusted-value',
        }

    def locked(self, revision):
        if revision != self.state[REVISION]:
            raise UKeyAuthError('Configuration changed')
        return nullcontext(self.state)

    def authenticate(self):
        return self.backend.authenticate(self.request, 'user', ukey_proof=self.proof)

    def test_success_uses_only_the_server_saved_challenge(self):
        self.assertIs(self.authenticate(), self.user)
        self.verify.assert_called_once_with('certificate', 'attached-signature', 'ab' * 32, 'user')
        self.backend._check_user_and_ukey_sn.assert_called_once_with('user', 'serial')
        with self.assertRaises(PermissionDenied):
            self.authenticate()
        self.verify.assert_called_once()

    def test_failed_or_timed_out_verification_does_not_release_challenge(self):
        for failure in (UKeyAuthError('Bad signature'), UKeyServiceError('Timed out')):
            self.proof['challenge_id'] = challenges.issue(self.request, 'login')['id']
            self.verify.reset_mock()
            self.verify.side_effect = failure
            with self.assertRaises(PermissionDenied):
                self.authenticate()
            self.verify.side_effect = None
            with self.assertRaises(PermissionDenied):
                self.authenticate()
            self.verify.assert_called_once()
            self.assertTrue(cache.get('ukey:consumed:' + self.proof['challenge_id']))

    def test_expired_or_other_session_or_missing_id_never_calls_verifier(self):
        token = self.proof['challenge_id']
        key = 'ukey:challenge:' + token
        original = cache.get(key)
        for changed in ({'expires': 0}, {'session': 'another-browser'}):
            cache.set(key, {**original, **changed}, 300)
            with self.assertRaises(PermissionDenied):
                self.authenticate()
        self.proof.pop('challenge_id')
        with self.assertRaises(PermissionDenied):
            self.authenticate()
        self.verify.assert_not_called()

    def test_config_change_during_remote_verification_cannot_complete_login(self):
        def change(*args):
            self.state = snapshot(**{REVISION: 'new-revision'})

        self.verify.side_effect = change
        with self.assertRaises(PermissionDenied):
            self.authenticate()
        self.verify.assert_called_once()

    def test_provider_change_between_initial_read_and_consume_is_rejected(self):
        self.state = snapshot(AUTH_UKEY_CA_PROVIDER='xjca', AUTH_UKEY_VENDOR='long_mai')
        key = 'ukey:challenge:' + self.proof['challenge_id']
        record = cache.get(key)
        cache.set(key, {**record, 'provider': 'xjca'}, 300)
        with patch.object(backends, 'get_snapshot', return_value=snapshot()):
            with self.assertRaises(PermissionDenied):
                self.authenticate()
        self.verify.assert_not_called()
