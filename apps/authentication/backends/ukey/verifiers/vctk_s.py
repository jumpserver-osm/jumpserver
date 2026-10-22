"""Verify existing JiDa UKey identities through the VCTK_S HTTP service."""
import re
from datetime import datetime, timezone

from asn1crypto import cms, pem
from django.utils.translation import gettext_lazy as _

from common.utils import get_logger
from ..clients.fisherman import (
    Certificate, MAX_CERT, SM2_OID, SVSError, decode_base64, strict_der,
)
from ..clients.vctk_s import MAX_P7_SIZE, VCTKSClient
from ..exceptions import UKeyAuthError, UKeyServiceError
from .base import BaseVerifier
from .builtin import BuiltinVerifier

logger = get_logger(__name__)

SIGNED_DATA_OIDS = {'1.2.840.113549.1.7.2', '1.2.156.10197.6.1.4.2.2'}
DATA_OIDS = {'1.2.840.113549.1.7.1', '1.2.156.10197.6.1.4.2.1'}
SM3_OID = '1.2.156.10197.1.401'
SHA256_OID = '2.16.840.1.101.3.4.2.1'


class VCTKSCertificateChoices(cms.CertificateChoices):
    _alternatives = [('certificate', Certificate), *cms.CertificateChoices._alternatives[1:]]


class VCTKSCertificateSet(cms.CertificateSet):
    _child_spec = VCTKSCertificateChoices


class VCTKSSignedData(cms.SignedData):
    _fields = [(name, VCTKSCertificateSet if name == 'certificates' else spec, *options)
               for name, spec, *options in cms.SignedData._fields]


class VCTKSContentInfo(cms.ContentInfo):
    # The vendor's GM P7 envelope uses GM/T 0010 content OIDs. Keep these
    # mappings local; changing asn1crypto's global maps would affect other CAs.
    _oid_specs = {
        **cms.ContentInfo._oid_specs,
        'signed_data': VCTKSSignedData,
        '1.2.156.10197.6.1.4.2.2': VCTKSSignedData,
    }


def certificate_algorithm(certificate):
    algorithm = certificate['tbs_certificate']['subject_public_key_info']['algorithm']
    if algorithm['algorithm'].native == 'rsa':
        return 'rsa'
    if (algorithm['algorithm'].dotted == SM2_OID
            or (algorithm['algorithm'].native == 'ec'
                and algorithm['parameters'].native == SM2_OID)):
        return 'sm2'
    raise ValueError('Unsupported issuing CA or signing certificate algorithm')


def checked_certificate(data, *, ca=False):
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_CERT:
        raise ValueError('Invalid certificate size')
    certificate = strict_der(Certificate, data)
    certificate_algorithm(certificate)
    extensions = certificate['tbs_certificate']['extensions']
    extension_ids = [extension['extn_id'].dotted for extension in extensions]
    if len(extension_ids) != len(set(extension_ids)):
        raise ValueError('Duplicate certificate extension')
    if bool(certificate.ca) != ca:
        raise ValueError('Incorrect certificate role')
    usage = certificate.key_usage_value
    if usage is not None and ('key_cert_sign' if ca else 'digital_signature') not in usage.native:
        raise ValueError('Incorrect certificate key usage')
    validity = certificate['tbs_certificate']['validity']
    if not validity['not_before'].native <= datetime.now(timezone.utc) <= validity['not_after'].native:
        raise ValueError('Certificate outside validity period')
    return certificate


def load_issuing_ca(value):
    if (not isinstance(value, str) or len(value) > 32768
            or not re.fullmatch(r'\s*-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+'
                                r'-----END CERTIFICATE-----\s*', value)):
        raise ValueError('A single PEM issuing CA is required')
    return checked_certificate(pem.unarmor(value.encode('ascii'))[2], ca=True)


def _signer_matches(sid, certificate):
    if sid.name == 'issuer_and_serial_number':
        return (sid.chosen['issuer'].dump() == certificate.issuer.dump()
                and sid.chosen['serial_number'].native == certificate.serial_number)
    return (sid.name == 'subject_key_identifier' and certificate.key_identifier is not None
            and sid.chosen.native == certificate.key_identifier)


def check_detached_signer(signature, certificate):
    if not isinstance(signature, bytes) or not 1 <= len(signature) <= MAX_P7_SIZE:
        raise ValueError('Invalid P7 signature size')
    content = strict_der(VCTKSContentInfo, signature)
    if content['content_type'].dotted not in SIGNED_DATA_OIDS:
        raise ValueError('Detached SignedData required')
    signed = content['content']
    encapsulated = signed['encap_content_info']
    if (encapsulated['content_type'].dotted not in DATA_OIDS
            or encapsulated['content'].native is not None):
        raise ValueError('Detached data required')
    signers = signed['signer_infos']
    if len(signers) != 1:
        raise ValueError('Exactly one signer required')
    signer = signers[0]
    # A P7 may include a certificate chain. Resolve its signer, rather than
    # assuming the first (or only) certificate belongs to the UKey.
    matches = [
        item.chosen for item in signed['certificates']
        if item.name == 'certificate' and _signer_matches(signer['sid'], item.chosen)
    ]
    if len(matches) != 1 or matches[0].dump() != certificate.dump():
        raise ValueError('P7 signer differs from submitted certificate')
    expected_digest = SM3_OID if certificate_algorithm(certificate) == 'sm2' else SHA256_OID
    if (signer['digest_algorithm']['algorithm'].dotted != expected_digest
            or {item['algorithm'].dotted for item in signed['digest_algorithms']} != {expected_digest}
            or not signer['signature'].native):
        raise ValueError('Incorrect P7 signing algorithm')


class VCTKSVerifier(BaseVerifier):
    def __init__(self, url='', *, issuing_ca='', tls_verify='system', tls_ca_cert='',
                 connect_timeout=3, read_timeout=5):
        self.issuing_ca = issuing_ca
        self.connection = dict(
            url=url, tls_verify=tls_verify, tls_ca_cert=tls_ca_cert,
            connect_timeout=connect_timeout, read_timeout=read_timeout,
        )

    def _client(self):
        return VCTKSClient(**self.connection)

    def validate_config(self):
        try:
            self._client()
            load_issuing_ca(self.issuing_ca)
        except Exception:
            raise UKeyAuthError(_(
                'Check the VCTK_S service URL, HTTPS trust settings and issuing CA certificate.'
            )) from None

    def verify_proof(self, cert, signature, challenge, username=''):
        stage = 'parse'
        try:
            if not isinstance(challenge, str) or not re.fullmatch('[0-9a-f]{32}', challenge):
                raise ValueError('Invalid challenge')
            certificate = checked_certificate(decode_base64(cert, MAX_CERT))
            signature_bytes = decode_base64(signature, MAX_P7_SIZE)
            issuer = load_issuing_ca(self.issuing_ca)
            stage = 'signer_identity'
            check_detached_signer(signature_bytes, certificate)
            stage = 'certificate_trust'
            if (certificate.issuer.dump() != issuer.subject.dump()
                    or (certificate.authority_key_identifier is not None and issuer.key_identifier is not None
                        and certificate.authority_key_identifier != issuer.key_identifier)):
                raise ValueError('Incorrect certificate issuer')
            claims = BuiltinVerifier(self.issuing_ca).verify_certificate(cert, username)
        except UKeyAuthError:
            raise
        except Exception as exc:
            logger.warning('VCTK_S proof rejected: stage=%s exception=%s', stage, type(exc).__name__)
            raise UKeyAuthError(_('VCTK_S certificate or signature verification failed.')) from None
        try:
            self._client().verify_signed_data(challenge, signature)
        except Exception as exc:
            logger.warning('VCTK_S proof rejected: stage=server exception=%s', type(exc).__name__)
            raise UKeyServiceError(_('VCTK_S server verification failed. Check the service settings.')) from None
        return claims

    def test_connection(self):
        try:
            self._client().get_version()
        except SVSError as exc:
            raise UKeyServiceError(str(exc)) from None
        return {
            'connection': True, 'verification': False,
            'msg': _('VCTK_S version check passed. UKey signature and certificate verification '
                     'have not been tested. Settings were not saved.'),
        }
