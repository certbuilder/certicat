from __future__ import print_function

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from certicat.result import CerticatResult


class Certicat(object):
    _simple_members = ["serial_number", "not_valid_before", "not_valid_after"]
    _tuple_members = [("issuer", "issuer_name"), ("subject", "subject_name")]

    def __init__(self, certificate):
        self._old_cert = certificate
        self._builder = x509.CertificateBuilder()

    def _get_member_simple(self, old_cert_member_name, builder_member_name):
        return getattr(self._builder, builder_member_name)(
            getattr(self._old_cert, old_cert_member_name)
        )

    def _get_extensions(self):
        return (ext for ext in self._old_cert.extensions)

    def _get_private_key(self):
        private_key = None
        pub_key = getattr(self._old_cert, "public_key")

        if isinstance(pub_key(), RSAPublicKey):
            private_key = rsa.generate_private_key(
                public_exponent=pub_key().public_numbers().e,
                key_size=pub_key().key_size,
                backend=default_backend(),
            )
        elif isinstance(pub_key(), EllipticCurvePublicKey):
            private_key = ec.generate_private_key(
                curve=pub_key().curve, backend=default_backend()
            )

        return private_key

    def _get_sign_algorithm(self):
        return getattr(self._old_cert, "signature_hash_algorithm")

    def get_copy(self, signing_key=None):
        for member in self._simple_members:
            self._builder = self._get_member_simple(
                old_cert_member_name=member, builder_member_name=member
            )

        for old_cert_member_name, builder_member_name in self._tuple_members:
            self._builder = self._get_member_simple(
                old_cert_member_name=old_cert_member_name,
                builder_member_name=builder_member_name,
            )

        for extension in self._get_extensions():
            if (
                not isinstance(extension.value, x509.AuthorityKeyIdentifier)
                and not isinstance(extension.value, x509.SubjectKeyIdentifier)
                and not isinstance(
                    extension.value,
                    x509.PrecertificateSignedCertificateTimestamps,
                )
            ):

                self._builder = self._builder.add_extension(
                    extension.value, extension.critical
                )

        priv_key = self._get_private_key()
        signing_key = priv_key if signing_key is None else signing_key
        public_key = priv_key.public_key()

        self._builder = self._builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                signing_key.public_key()
            ),
            False,
        )

        self._builder = self._builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), False
        )

        self._builder = self._builder.public_key(public_key)
        return CerticatResult(
            certificate=self._builder.sign(
                private_key=signing_key,
                algorithm=self._get_sign_algorithm(),
                backend=default_backend(),
            ),
            key=priv_key,
        )
