from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.interfaces.IEntryPoint import IEntryPoint
from pytypes.source.examples.src.SocialRecovery.SocialRecovery import SocialRecovery
from pytypes.source.examples.node_modules.sentinellist.src.SentinelList4337 import SentinelList4337Lib

from .utils import *


class SocialRecoveryTest(ExamplesTest):
    beneficiary: Account
    social_recovery: SocialRecovery
    acc: MSAAdvanced

    guardians: List[Account]
    threshold: int

    def pre_sequence(self) -> None:
        super().pre_sequence()

        self.beneficiary = Account(1)
        self.social_recovery = SocialRecovery.deploy()
        self.acc = self.new_smart_account()

        self.guardians = sorted(random.sample(chain.accounts, random_int(1, len(chain.accounts))), reverse=True)
        self.threshold = random_int(1, len(self.guardians))
        op, _ = self.user_op(
            self.acc,
            self.simple_validator,
            abi.encode_call(self.acc.installModule, [1, self.social_recovery, abi.encode(uint(self.threshold), list(reversed(self.guardians)))])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        self.validators[self.acc].insert(0, self.social_recovery)

    def post_sequence(self) -> None:
        super().post_sequence()

        index = self.validators[self.acc].index(self.social_recovery)
        prev_validator = self.validators[self.acc][index - 1] if index > 0 else Account(1)

        op, _ = self.user_op(
            self.acc,
            self.simple_validator,
            abi.encode_call(self.acc.uninstallModule, [1, self.social_recovery, abi.encode(prev_validator, b"")])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_add_guardian()

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_remove_guardian()

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_recover()

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_set_threshold()

    @flow()
    def flow_set_threshold(self):
        threshold = random_int(max(0, len(self.guardians) - 1), len(self.guardians) + 1)
        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.social_recovery,
            abi.encode_call(self.social_recovery.setThreshold, [threshold])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        if threshold > len(self.guardians):
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SocialRecovery.InvalidThreshold())
        elif threshold == 0:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SocialRecovery.InvalidThreshold())
        else:
            assert e.success
            self.threshold = threshold

    @flow()
    def flow_add_guardian(self):
        new_guardian = random_account()
        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.social_recovery,
            abi.encode_call(self.social_recovery.addGuardian, [new_guardian])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        if new_guardian in self.guardians:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(new_guardian.address))
        else:
            assert e.success
            self.guardians.insert(0, new_guardian)

    @flow()
    def flow_remove_guardian(self):
        if len(self.guardians) == 0 or len(self.guardians) == self.threshold:
            return

        index = random_int(0, len(self.guardians) - 1)
        if index == 0:
            prev_guardian = Account(1)  # sentinel
        else:
            prev_guardian = self.guardians[index - 1]
        guardian = self.guardians[index]
        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.social_recovery,
            abi.encode_call(self.social_recovery.removeGuardian, [prev_guardian, guardian])
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        self.guardians.remove(guardian)

    @flow()
    def flow_recover(self):
        op, hash = self.erc7579_execute_op(
            self.acc,
            self.social_recovery,
            self.simple_validator,
            abi.encode_call(self.simple_validator.isModuleType, [uint(0)])  # dummy call
        )
        signatures = [guard.sign(hash) for guard in random.sample(self.guardians, k=min(self.threshold, len(self.guardians)))]
        op.signature = bytearray(b"".join(signatures))

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

    @invariant()
    def invariant_get_guardians(self):
        assert self.social_recovery.getGuardians(self.acc) == [g.address for g in self.guardians]


@chain.connect()
@on_revert(lambda e: print(e.tx.call_trace if e.tx else "Call reverted"))
def test_social_recovery_fuzz():
    SocialRecoveryTest().run(10, 1000)
