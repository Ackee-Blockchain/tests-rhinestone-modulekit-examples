from collections import defaultdict
from typing import Optional, Tuple, Dict
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.interfaces.PackedUserOperation import PackedUserOperation
from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.core.EntryPoint import EntryPoint
from pytypes.source.examples.node_modules.erc7579.src.MSAAdvanced import MSAAdvanced
from pytypes.source.examples.node_modules.erc7579.src.utils.Bootstrap import Bootstrap
from pytypes.source.examples.node_modules.erc7579.src.modules.SimpleExecutionValidator import SimpleExecutionValidator


ENTRY_POINY = EntryPoint("0x0000000071727De22E5E9d8BAf0edAc6f37da032")


class ExamplesTest(FuzzTest):
    bootstrap: Bootstrap
    simple_validator: SimpleExecutionValidator

    smart_accounts: List[MSAAdvanced]
    validators: Dict[Account, List[Account]]
    executors: Dict[Account, List[Account]]
    hooks: Dict[Account, Account]
    nonces: Dict[Account, Dict[Account, uint]]

    def pre_sequence(self) -> None:
        self.smart_accounts = []
        self.validators = defaultdict(list)
        self.executors = defaultdict(list)
        self.hooks = {}  # only one hook may be set per account
        self.nonces = defaultdict(lambda: defaultdict(lambda: uint(0)))

        e = EntryPoint.deploy()
        ENTRY_POINY.code = e.code
        chain.chain_interface.set_storage_at(str(ENTRY_POINY.address), 2, chain.chain_interface.get_storage_at(str(e.address), 2))

        self.bootstrap = Bootstrap.deploy()
        self.simple_validator = SimpleExecutionValidator.deploy()

    def new_smart_account(self, initial_validator: Optional[Account] = None, validator_data=b"") -> MSAAdvanced:
        if initial_validator is None:
            initial_validator = self.simple_validator

        acc = MSAAdvanced.deploy()
        acc.initializeAccount(abi.encode(self.bootstrap, abi.encode_call(self.bootstrap.singleInitMSA, [initial_validator, validator_data])))

        self.validators[acc].append(initial_validator)
        self.smart_accounts.append(acc)

        return acc

    def custom_user_op(self, smart_account: Account, nonce: uint, *, data: bytes = b"") -> Tuple[PackedUserOperation, bytes32]:
        op = PackedUserOperation(
            sender=smart_account.address,
            nonce=uint(nonce),
            initCode=bytearray(b""),
            callData=bytearray(data),
            accountGasLimits=bytes32(abi.encode_packed(uint128(10_000_000), uint128(10_000_000))),
            preVerificationGas=uint(0),
            gasFees=bytes32(0),
            paymasterAndData=bytearray(b""),
            signature=bytearray(b"")
        )
        encoded_op = abi.encode(
            op.sender,
            op.nonce,
            keccak256(op.initCode),
            keccak256(op.callData),
            op.accountGasLimits,
            op.preVerificationGas,
            op.gasFees,
            keccak256(op.paymasterAndData),
        )
        hash = keccak256(abi.encode(keccak256(encoded_op), ENTRY_POINY, chain.chain_id))
        return op, hash


    def user_op(self, smart_account: Account, validator: Account, data: bytes = b"") -> Tuple[PackedUserOperation, bytes32]:
        n = self.nonces[smart_account][validator]
        self.nonces[smart_account][validator] += 1

        nonce = int.from_bytes(bytes(validator.address) + n.to_bytes(12, "big"))
        return self.custom_user_op(smart_account, nonce, data=data)


    def erc7579_execute_op(self, smart_account: Account, validator: Account, target: Account, calldata: bytes, value: int = 0) -> Tuple[PackedUserOperation, bytes32]:
        return self.user_op(
            smart_account,
            validator,
            data=abi.encode_call(MSAAdvanced.execute, [bytes32(0), abi.encode_packed(target, uint(value), calldata)])
        )
