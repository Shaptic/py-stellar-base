import hashlib
import binascii

from typing import Union

from .fee_bump_transaction_envelope import FeeBumpTransactionEnvelope
from .transaction_envelope import TransactionEnvelope
from .transaction import Transaction
from .utils import is_fee_bump_transaction
from .strkey import StrKey
from . import xdr

__all__ = ["parse_transaction_envelope_from_xdr", "claimable_balance_id"]


def parse_transaction_envelope_from_xdr(
    xdr: str, network_passphrase: str
) -> Union[TransactionEnvelope, FeeBumpTransactionEnvelope]:
    """When you are not sure whether your XDR belongs to
        :py:class:`TransactionEnvelope <stellar_transaction_envelope.TransactionEnvelope>`
        or :py:class:`FeeBumpTransactionEnvelope <stellar_fee_bump_transaction_envelope.FeeBumpTransactionEnvelope>`,
        you can use this helper function.

    :param xdr: Transaction envelope XDR
    :param network_passphrase: The network to connect to for verifying and retrieving
        additional attributes from. (ex. 'Public Global Stellar Network ; September 2015')
    :raises: :exc:`ValueError <stellar_exceptions.ValueError>` - XDR is neither :py:class:`TransactionEnvelope <stellar_transaction_envelope.TransactionEnvelope>`
        nor :py:class:`FeeBumpTransactionEnvelope <stellar_fee_bump_transaction_envelope.FeeBumpTransactionEnvelope>`
    """
    if is_fee_bump_transaction(xdr):
        return FeeBumpTransactionEnvelope.from_xdr(xdr, network_passphrase)
    return TransactionEnvelope.from_xdr(xdr, network_passphrase)

def claimable_balance_id(tx: Transaction, op_index: int) -> str:
    """Calculates a claimable balance ID (as a hex string) for a particular
        operation w/in a :py:class:`TransactionEnvelope
        <stellar_transaction.Transaction>`.

    :param tx: Transaction object
    :param op_index: which operation within the transaction contains the
        :py:class:`CreateClaimableBalance
        <stellar_operation.create_claimable_balance.CreateClaimableBalance>`.
    """
    if op_index < 0 or op_index >= len(tx.operations):
        raise ValueError("invalid operation index")

    op_id = xdr.OperationID(
        xdr.EnvelopeType.ENVELOPE_TYPE_OP_ID,
        xdr.OperationIDId(
            xdr.AccountID(xdr.Uint256(
                StrKey.decode_ed25519_public_key(tx.source.account_id)
            )),
            xdr.SequenceNumber(xdr.Int64(tx.sequence)),
            xdr.Uint32(op_index),
        )
    )

    balance_id_xdr = xdr.ClaimableBalanceID(
        xdr.ClaimableBalanceIDType.CLAIMABLE_BALANCE_ID_TYPE_V0,
        xdr.Hash(hashlib.sha256(op_id.to_xdr_bytes()).digest())
    )

    return binascii.hexlify(balance_id_xdr.to_xdr_bytes()).decode("ascii")
