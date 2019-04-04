from __future__ import print_function

from cryptography import x509


class CerticatResult(object):
    _attrs = [
        "serial_number",
        "not_valid_before",
        "not_valid_after",
        "issuer",
        "subject",
    ]
    _excluded_extentions = [
        x509.AuthorityKeyIdentifier,
        x509.SubjectKeyIdentifier,
        x509.PrecertificateSignedCertificateTimestamps,
    ]

    def __init__(self, certificate, key):
        self.certificate = certificate
        self.key = key

    def __eq__(self, other):
        if isinstance(self.certificate, other.__class__):
            return all(
                [
                    exta == extb
                    for exta, extb in zip(
                        self.certificate.extensions, other.extensions
                    )
                    if not any(
                        [
                            isinstance(exta.value, excluded_ext)
                            for excluded_ext in self._excluded_extentions
                        ]
                    )
                ]
            ) and all(
                [
                    getattr(self.certificate, attr) == getattr(other, attr)
                    for attr in self._attrs
                ]
            )

        return False
