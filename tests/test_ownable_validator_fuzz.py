import logging
from wake.testing import *

from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.interfaces.IEntryPoint import IEntryPoint
from pytypes.source.examples.src.OwnableValidator.OwnableValidator import OwnableValidator
from pytypes.source.examples.node_modules.sentinellist.src.SentinelList4337 import SentinelList4337Lib

from .utils import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class OwnableValidatorTest(ExamplesTest):
    beneficiary: Account
    ownable_validator: OwnableValidator
    acc: MSAAdvanced

    owners: List[Account]

    def pre_sequence(self) -> None:
        super().pre_sequence()

        self.orders = {}
        self.beneficiary = Account(1)
        self.ownable_validator = OwnableValidator.deploy()
        self.acc = self.new_smart_account()

        self.owners = sorted(random.sample(chain.accounts, random_int(1, len(chain.accounts))), reverse=True)
        self.threshold = random_int(1, len(self.owners))
        op, _ = self.user_op(
            self.acc,
            self.simple_validator,
            abi.encode_call(self.acc.installModule, [1, self.ownable_validator, abi.encode(uint(self.threshold), list(reversed(self.owners)))]),
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        self.validators[self.acc].insert(0, self.ownable_validator)

    def post_sequence(self) -> None:
        super().post_sequence()

        index = self.validators[self.acc].index(self.ownable_validator)
        prev_validator = self.validators[self.acc][index - 1] if index > 0 else Account(1)

        op, _ = self.user_op(
            self.acc,
            self.simple_validator,
            abi.encode_call(self.acc.uninstallModule, [1, self.ownable_validator, abi.encode(prev_validator, b"")])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_add_owner()

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_remove_owner()

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_validate_user_op()

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_set_threshold()

    @flow()
    def flow_set_threshold(self):
        threshold = random_int(max(0, len(self.owners) - 1), len(self.owners) + 1)
        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.ownable_validator,
            abi.encode_call(self.ownable_validator.setThreshold, [threshold])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        if threshold > len(self.owners):
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(OwnableValidator.InvalidThreshold())
        elif threshold == 0:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(OwnableValidator.InvalidThreshold())
        else:
            assert e.success
            self.threshold = threshold

            logger.info(f"Set threshold to {threshold}")

    @flow()
    def flow_add_owner(self):
        owner = random.choice(chain.accounts)
        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.ownable_validator,
            abi.encode_call(self.ownable_validator.addOwner, [owner])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        if owner in self.owners:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(owner.address))
        else:
            assert e.success
            self.owners.insert(0, owner)

            logger.info(f"Added owner {owner}")

    @flow()
    def flow_remove_owner(self):
        if len(self.owners) == 0 or len(self.owners) == self.threshold:
            return

        index = random_int(0, len(self.owners) - 1)
        if index == 0:
            prev_owner = Account(1)
        else:
            prev_owner = self.owners[index - 1]
        owner = self.owners[index]
        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.ownable_validator,
            abi.encode_call(self.ownable_validator.removeOwner, [prev_owner, owner])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        self.owners.remove(owner)

        logger.info(f"Removed owner {owner}")

    @flow()
    def flow_validate_user_op(self):
        op, hash = self.erc7579_execute_op(
            self.acc,
            self.ownable_validator,
            self.ownable_validator,
            abi.encode_call(self.ownable_validator.isModuleType, [uint(0)])  # dummy call
        )
        signatures = [owner.sign(hash) for owner in random.sample(self.owners, k=min(self.threshold, len(self.owners)))]
        op.signature = bytearray(b"".join(signatures))

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

    @invariant()
    def invariant_get_owners(self):
        assert self.ownable_validator.getOwners(self.acc) == [o.address for o in self.owners]

    @invariant()
    def invariant_is_valid_signature(self):
        hash = random_bytes(32, 32)
        signatures = [owner.sign(hash) for owner in random.sample(self.owners, k=min(self.threshold, len(self.owners)))]

        assert self.acc.isValidSignature(hash, bytes(self.ownable_validator.address) + b"".join(signatures))

    @invariant()
    def invariant_is_valid_signature_with_data(self):
        owners = sorted(random.sample(chain.accounts, k=random_int(0, len(chain.accounts))))
        threshold = random_int(0, len(set(owners)))

        hash = random_bytes(32, 32)
        signatures = [owner.sign(hash) for owner in random.choices(owners, k=min(threshold, len(owners)))]

        assert self.ownable_validator.validateSignatureWithData(
            hash,
            b"".join(signatures), abi.encode(uint(threshold), owners),
            from_=random_account(),
        ) == (len(set(signatures)) >= threshold and threshold > 0)


@chain.connect()
def test_ownable_validator_fuzz():
    OwnableValidatorTest().run(10, 1000)
