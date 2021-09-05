from enum import IntEnum
from typing import Union

from . import xdr as stellar_xdr
from .__version__ import __issues__
from .exceptions import ValueError, TypeError
from .strkey import StrKey

__all__ = ["SignerKey", "SignerKeyType"]


class SignerKeyType(IntEnum):
    SIGNER_KEY_TYPE_ED25519 = 0
    SIGNER_KEY_TYPE_PRE_AUTH_TX = 1
    SIGNER_KEY_TYPE_HASH_X = 2


class SignerKey:
    """The :class:`SignerKey` object, which represents an account signer key on Stellar's network.

    Instead of instantiating the class directly, we recommend using one of
    several class methods:

    * :meth:`SignerKey.ed25519_public_key`
    * :meth:`SignerKey.pre_auth_tx`
    * :meth:`SignerKey.sha256_hash`

    :param signer_key_type: The key type.
    :param signer_key: The key value.
    """

    def __init__(self, signer_key_type: SignerKeyType, signer_key: Union[str, bytes]) -> "None":
        if not isinstance(signer_key_type, SignerKeyType):
            raise TypeError("signer_key_type must be SignerKeyType.")
        if not isinstance(signer_key, (str, bytes)):
            raise TypeError("signer_key must be str or bytes.")

        self.signer_key_type: SignerKeyType = signer_key_type
        if isinstance(signer_key, str):
            self.signer_key: str = signer_key
            if self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_ED25519:
                self._signer_key_bytes: bytes = StrKey.decode_ed25519_public_key(
                    signer_key
                )
            elif self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX:
                self._signer_key_bytes = StrKey.decode_pre_auth_tx(signer_key)
            elif self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_HASH_X:
                self._signer_key_bytes = StrKey.decode_sha256_hash(signer_key)
            else:
                raise ValueError(f"Unexpected signer key type: {self.signer_key_type}")
        elif isinstance(signer_key, bytes):
            self._signer_key_bytes: bytes = signer_key
            if self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_ED25519:
                self.signer_key: str = StrKey.encode_ed25519_public_key(
                    signer_key
                )
            elif self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX:
                self.signer_key = StrKey.encode_pre_auth_tx(signer_key)
            elif self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_HASH_X:
                self.signer_key = StrKey.encode_sha256_hash(signer_key)
            else:
                raise ValueError(f"Unexpected signer key type: {self.signer_key_type}")
        else:
            raise ValueError("signer_key must be a str or bytes.")


    @classmethod
    def ed25519_public_key(cls, account_id: Union[str, bytes]) -> "SignerKey":
        """Create ED25519 PUBLIC KEY Signer from account id.

        :param account_id: account id
        :return: ED25519 PUBLIC KEY Signer
        :raises:
            :exc:`Ed25519PublicKeyInvalidError <stellar_sdk.exceptions.Ed25519PublicKeyInvalidError>`: if ``account_id``
            is not a valid ed25519 public key.
        """
        signer_key_type = SignerKeyType.SIGNER_KEY_TYPE_ED25519
        if isinstance(account_id, bytes):
            key: str = StrKey.encode_ed25519_public_key(account_id)
        else:
            key = account_id
        return cls(signer_key_type, key)

    @classmethod
    def pre_auth_tx(cls, pre_auth_tx_hash: Union[str, bytes]) -> "SignerKey":
        """Create Pre AUTH TX Signer from the sha256 hash of a transaction,
        click `here <https://www.stellar.org/developers/guides/concepts/multi-sig.html#pre-authorized-transaction>`__ for more information.

        :param pre_auth_tx_hash: The sha256 hash of a transaction.
        :return: Pre AUTH TX Signer
        """

        signer_key_type = SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX
        if isinstance(pre_auth_tx_hash, bytes):
            key: str = StrKey.encode_pre_auth_tx(pre_auth_tx_hash)
        else:
            key = pre_auth_tx_hash
        return cls(signer_key_type, key)

    @classmethod
    def sha256_hash(cls, sha256_hash: Union[str, bytes]) -> "SignerKey":
        """Create SHA256 HASH Signer from a sha256 hash of a preimage,
        click `here <https://www.stellar.org/developers/guides/concepts/multi-sig.html#hashx>`__ for more information.

        :param sha256_hash: a sha256 hash of a preimage
        :return: SHA256 HASH Signer
        """
        signer_key_type = SignerKeyType.SIGNER_KEY_TYPE_HASH_X
        if isinstance(sha256_hash, bytes):
            key: str = StrKey.encode_sha256_hash(sha256_hash)
        else:
            key = sha256_hash
        return cls(signer_key_type, key)

    def to_xdr_object(self) -> stellar_xdr.SignerKey:
        """Returns the xdr object for this SignerKey object.

        :return: XDR Signer object
        """
        if self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_ED25519:
            signer_key_type = stellar_xdr.SignerKeyType.SIGNER_KEY_TYPE_ED25519
            return stellar_xdr.SignerKey(
                type=signer_key_type,
                ed25519=stellar_xdr.Uint256(self._signer_key_bytes),
            )
        elif self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX:
            signer_key_type = stellar_xdr.SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX
            return stellar_xdr.SignerKey(
                type=signer_key_type,
                pre_auth_tx=stellar_xdr.Uint256(self._signer_key_bytes),
            )
        elif self.signer_key_type == SignerKeyType.SIGNER_KEY_TYPE_HASH_X:
            signer_key_type = stellar_xdr.SignerKeyType.SIGNER_KEY_TYPE_HASH_X
            return stellar_xdr.SignerKey(
                type=signer_key_type, hash_x=stellar_xdr.Uint256(self._signer_key_bytes)
            )
        else:
            raise ValueError(f"Unexpected signer key type: {self.signer_key_type}")

    @classmethod
    def from_xdr_object(cls, xdr_object: stellar_xdr.SignerKey) -> "SignerKey":
        """Create a :class:`SignerKey` from an XDR SignerKey object.

        :param xdr_object: The XDR SignerKey object.
        :return: A new :class:`SignerKey` object from the given XDR SignerKey object.
        """
        if xdr_object.type == stellar_xdr.SignerKeyType.SIGNER_KEY_TYPE_ED25519:
            assert xdr_object.ed25519 is not None
            account_id = StrKey.encode_ed25519_public_key(xdr_object.ed25519.uint256)
            return cls.ed25519_public_key(account_id)
        elif xdr_object.type == stellar_xdr.SignerKeyType.SIGNER_KEY_TYPE_PRE_AUTH_TX:
            assert xdr_object.pre_auth_tx is not None
            return cls.pre_auth_tx(xdr_object.pre_auth_tx.uint256)
        elif xdr_object.type == stellar_xdr.SignerKeyType.SIGNER_KEY_TYPE_HASH_X:
            assert xdr_object.hash_x is not None
            return cls.sha256_hash(xdr_object.hash_x.uint256)
        else:
            raise ValueError(
                f"This is an unknown signer type, please consider creating an issuer at {__issues__}."
            )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented  # pragma: no cover
        return (
            self.signer_key_type == other.signer_key_type
            and self.signer_key == other.signer_key
        )

    def __str__(self):
        return f"<SignerKey [signer_key_type={self.signer_key_type}, signer_key={self.signer_key}]>"
