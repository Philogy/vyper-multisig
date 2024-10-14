#pragma version ^0.4.0
#pragma optimize codesize

from snekmate.utils import eip712_domain_separator

initializes: eip712_domain_separator

_MAX_MEMBER_INPUT: constant(uint256) = 64
_SIGNATURE_BYTES: constant(uint256) = 65
_MULTISIG_TX_TYPEHASH: constant(bytes32) = keccak256("MultisigTransaction(address target,bytes payload,uint256 value,uint256 nonce)")
_SIG_V_OFFSET: constant(uint256) = 0
_SIG_R_OFFSET: constant(uint256) = 1
_SIG_S_OFFSET: constant(uint256) = 33

is_member: public(HashMap[address, bool])
total_members: public(uint128)
threshold: public(uint128)
_used_nonces_bitmap: HashMap[uint256, uint256]


@deploy
def __init__(members: DynArray[address, _MAX_MEMBER_INPUT], threshold: uint128):
    assert convert(threshold, uint256) <= len(members), 'Threshold larger than total members'
    assert threshold > 0, 'Threshold must be at least 1'

    eip712_domain_separator.__init__("Multisig", "1")

    self.total_members = convert(len(members), uint128)
    self.threshold = threshold

    # Can't compare addresses so convert to uint.
    last_addr: uint256 = 0
    for member: address in members:
        self.is_member[member] = True
        addr: uint256 = convert(member, uint256)
        assert addr > last_addr, 'Duplicate or out-of-order members'
        last_addr = addr

@external
@payable
def __default__():
    pass

@external
def add_member(new_member: address):
    self._check_caller_self()
    assert not self.is_member[new_member], 'Already member'
    self.total_members += 1
    self.is_member[new_member] = True

@external
def remove_member(member: address):
    self._check_caller_self()
    assert self.is_member[member], 'Not member'
    # Validate we can still meet the threshold
    new_total: uint128 = self.total_members - 1
    assert new_total >= self.threshold, 'Cannot remove member when total_members == threshold'
    self.total_members = new_total
    self.is_member[member] = False

@external
def change_threshold(new_threshold: uint128):
    self._check_caller_self()
    assert convert(new_threshold, uint256) <= _MAX_MEMBER_INPUT, 'New threshold exceeds max inputable members'
    assert new_threshold <= self.total_members, 'New threshold exceeds total members'
    self.threshold = new_threshold

@external
def execute(
    target: address,
    with_value: uint256,
    data: Bytes[2048],
    nonce: uint256,
    packed_sigs: Bytes[_SIGNATURE_BYTES * _MAX_MEMBER_INPUT]
):
    threshold: uint256 = convert(self.threshold, uint256)
    assert len(packed_sigs) // _SIGNATURE_BYTES >= threshold, 'Below threshold'

    struct_hash: bytes32 = keccak256(abi_encode(
        _MULTISIG_TX_TYPEHASH,
        target,
        keccak256(data),
        with_value,
        nonce
    ))
    digest_hash: bytes32 = eip712_domain_separator._hash_typed_data_v4(struct_hash)

    last_addr: uint256 = 0
    for i: uint256 in range(threshold, bound=_MAX_MEMBER_INPUT):
        sig_offset: uint256 = unsafe_mul(i, _SIGNATURE_BYTES)
        v: uint8 = convert(slice(packed_sigs, unsafe_add(sig_offset, _SIG_V_OFFSET), 1), uint8)
        r: bytes32 = extract32(packed_sigs, unsafe_add(sig_offset, _SIG_R_OFFSET))
        s: bytes32 = extract32(packed_sigs, unsafe_add(sig_offset, _SIG_S_OFFSET))
        supposed_member: address = ecrecover(digest_hash, v, r, s)
        assert self.is_member[supposed_member], 'Not member'
        addr: uint256 = convert(supposed_member, uint256)
        assert addr > last_addr, 'Duplicate signers or out-of-order'
        last_addr = addr

    raw_call(target, data, value=with_value)

    self._check_and_use_nonce(nonce)


def _check_and_use_nonce(nonce: uint256):
    key: uint256 = nonce >> 8
    word: uint256 = self._used_nonces_bitmap[key]
    bit_flag: uint256 = 1 << (nonce & convert(0xff, uint256))
    assert word & bit_flag == 0, 'Nonce already used'
    self._used_nonces_bitmap[key] = word | bit_flag

def _check_caller_self():
    assert msg.sender == self, "Operation must be authorized by multisig"
