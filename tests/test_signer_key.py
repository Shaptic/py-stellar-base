import pytest

from stellar_sdk import SignerKey, SignerKeyType


class TestSignerKey:
    ed25519_strkey = "GBVNFFD52AAKLDYGTFNXQDH2CJJIP3NOBD7AXUCYBQ2RE5EGNOKBFZSX"
    ed25519_bytes = b"j\xd2\x94}\xd0\x00\xa5\x8f\x06\x99[x\x0c\xfa\x12R\x87\xed\xae\x08\xfe\x0b\xd0X\x0c5\x12t\x86k\x94\x12"

    @pytest.mark.parametrize(
        "key", [ed25519_strkey, ed25519_bytes], ids=["string", "bytes"]
    )
    def test_ed25519_public_key(self, key):
        signer_key = SignerKey.ed25519_public_key(key)
        assert signer_key.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_ED25519
        assert signer_key.signer_key == self.ed25519_strkey
        assert signer_key._signer_key_bytes == self.ed25519_bytes
        xdr = "AAAAAGrSlH3QAKWPBplbeAz6ElKH7a4I/gvQWAw1EnSGa5QS"
        xdr_object = signer_key.to_xdr_object()
        assert xdr_object.to_xdr() == xdr
        assert SignerKey.from_xdr_object(xdr_object) == signer_key
        assert (
            signer_key.__str__()
            == f"<SignerKey [signer_key_type={SignerKeyType.SIGNER_KEY_TYPE_ED25519}, signer_key={self.ed25519_strkey}]>"
        )

    pre_auth_tx_strkey = "TDJAMYS3SYY2Z5Q7MAHIKMSMMAKQKGPTQV27TCJSFIHEJLGM764V5DYP"
    pre_auth_tx_bytes = b"\xd2\x06b[\x961\xac\xf6\x1f`\x0e\x852L`\x15\x05\x19\xf3\x85u\xf9\x892*\x0eD\xac\xcc\xff\xb9^"

    @pytest.mark.parametrize(
        "key", [pre_auth_tx_strkey, pre_auth_tx_bytes], ids=["string", "bytes"]
    )
    def test_pre_auth_tx(self, key):
        signer_key = SignerKey.pre_auth_tx(key)
        assert signer_key.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX
        assert signer_key.signer_key == self.pre_auth_tx_strkey
        assert signer_key._signer_key_bytes == self.pre_auth_tx_bytes
        xdr = "AAAAAdIGYluWMaz2H2AOhTJMYBUFGfOFdfmJMioORKzM/7le"
        xdr_object = signer_key.to_xdr_object()
        assert xdr_object.to_xdr() == xdr
        assert SignerKey.from_xdr_object(xdr_object) == signer_key
        assert (
            signer_key.__str__()
            == f"<SignerKey [signer_key_type={SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX}, signer_key={self.pre_auth_tx_strkey}]>"
        )

    sha256_hash_strkey = "XDJAMYS3SYY2Z5Q7MAHIKMSMMAKQKGPTQV27TCJSFIHEJLGM764V4H5W"
    sha256_hash_bytes = b"\xd2\x06b[\x961\xac\xf6\x1f`\x0e\x852L`\x15\x05\x19\xf3\x85u\xf9\x892*\x0eD\xac\xcc\xff\xb9^"

    @pytest.mark.parametrize(
        "key", [sha256_hash_strkey, sha256_hash_bytes], ids=["string", "bytes"]
    )
    def test_sha256_hash(self, key):
        signer_key = SignerKey.sha256_hash(key)
        assert signer_key.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_HASH_X
        assert signer_key.signer_key == self.sha256_hash_strkey
        assert signer_key._signer_key_bytes == self.sha256_hash_bytes
        xdr = "AAAAAtIGYluWMaz2H2AOhTJMYBUFGfOFdfmJMioORKzM/7le"
        xdr_object = signer_key.to_xdr_object()
        assert xdr_object.to_xdr() == xdr
        assert SignerKey.from_xdr_object(xdr_object) == signer_key
        assert (
            signer_key.__str__()
            == f"<SignerKey [signer_key_type={SignerKeyType.SIGNER_KEY_TYPE_HASH_X}, signer_key={self.sha256_hash_strkey}]>"
        )
