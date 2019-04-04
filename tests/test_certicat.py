import pytest
import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from certicat import Certicat

certificates = ["Cert", "RootCert"] + ["IntermCert%d" % i for i in range(1, 4)]


def check_pem(pem_data):
    orig_pem_cert = x509.load_pem_x509_certificate(
        str.encode(pem_data), default_backend()
    )
    pem_cert = Certicat(certificate=orig_pem_cert)
    pem_new_cert = pem_cert.get_copy()

    return pem_new_cert == orig_pem_cert


def check_der(der_data):
    orig_der_cert = x509.load_der_x509_certificate(der_data, default_backend())
    der_ccert = Certicat(certificate=orig_der_cert)
    der_new_cert = der_ccert.get_copy()

    return der_new_cert == orig_der_cert


def test_pem_certificates():
    results = []

    for certificate in certificates:
        certificate_path = os.path.join("tests", "%s.pem" % certificate)
        with open(certificate_path, "r") as cert:
            results.append(check_pem(pem_data="".join(cert.readlines())))


def test_der_certificates():
    results = []

    for certificate in certificates:
        certificate_path = os.path.join("tests", "%s.der" % certificate)
        with open(certificate_path, "rb") as cert:
            results.append(check_der(der_data=b"".join(cert.readlines())))
