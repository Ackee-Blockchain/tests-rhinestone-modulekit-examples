import logging
from collections import defaultdict
from dataclasses import dataclass
from ordered_set import OrderedSet
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.interfaces.PackedUserOperation import PackedUserOperation
from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.interfaces.IEntryPoint import IEntryPoint
from pytypes.source.examples.node_modules.sentinellist.src.SentinelList4337 import SentinelList4337Lib
from pytypes.source.examples.src.OwnableValidator.OwnableValidator import OwnableValidator
from pytypes.source.examples.src.SocialRecovery.SocialRecovery import SocialRecovery
from pytypes.source.examples.src.ScheduledTransfers.ScheduledTransfers import ScheduledTransfers
from pytypes.source.examples.src.ScheduledOrders.ScheduledOrders import ScheduledOrders
from pytypes.source.examples.src.RegistryHook.RegistryHook import RegistryHook
from pytypes.source.examples.node_modules.forgestd.src.interfaces.IERC20 import IERC20
from pytypes.registry.src.Registry import Registry
from pytypes.registry.src.DataTypes import AttestationRequest
from pytypes.registry.src.external.IExternalSchemaValidator import IExternalSchemaValidator
from pytypes.tests.MockResolver import MockResolver
from pytypes.source.examples.src.OwnableExecutor.OwnableExecutor import OwnableExecutor
from pytypes.source.examples.src.MultiFactor.MultiFactor import MultiFactor
from pytypes.source.examples.src.MultiFactor.DataTypes import Validator
from pytypes.source.examples.src.HookMultiPlexer.HookMultiPlexer import HookMultiplexer
from pytypes.source.examples.src.HookMultiPlexer.DataTypes import HookType
from pytypes.source.examples.src.DeadmanSwitch.DeadmanSwitch import DeadmanSwitch
from pytypes.source.examples.src.AutoSavings.AutoSavings import AutoSavings
from pytypes.modulekit.src.modules.utils.TrustedForwarder import TrustedForwarder
from pytypes.modulekit.src.interfaces.IERC7484 import IERC7484
from pytypes.source.examples.node_modules.erc7579.src.interfaces.IERC7579Account import Execution
from pytypes.source.examples.node_modules.solmate.src.test.utils.mocks.MockERC4626 import MockERC4626

from .utils import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


TOKENS = [
    IERC20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), # usdc
    IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7"), # usdt
    IERC20("0xB8c77482e45F1F44dE1745F52C74426C631bDD52"), # bnb
    IERC20("0x6b175474e89094c44da98b954eedeac495271d0f"), # dai
    IERC20("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2"), # weth
    IERC20("0x80fB784B7eD66730e8b1DBd9820aFD29931aab03"), # lend
    IERC20("0xaba8cac6866b83ae4eec97dd07ed254282f6ad8a"), # yamv2
    IERC20("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"), # mkr
    IERC20("0xdb25f211ab05b1c97d595516f45794528a807ad8"), # eurs
    IERC20("0x1f9840a85d5af5bf1d1762f925bdaddc4201f984"), # uni
]


@dataclass
class TransferOrder:
    execute_interval: uint
    max_executions_count: uint
    start: uint
    recipient: Account
    token: IERC20
    amount: uint
    enabled: bool = True
    last_execution: uint = 0
    executions_count: uint = 0

    @property
    def payload(self) -> bytes:
        return abi.encode_packed(
            uint48(self.execute_interval),
            uint16(self.max_executions_count),
            uint48(self.start),
            abi.encode(self.recipient, self.token, self.amount)
        )


@dataclass
class SwapOrder:
    execute_interval: uint
    max_executions_count: uint
    start: uint
    token_in: IERC20
    token_out: IERC20
    amount_in: uint
    sqrt_price_limit_x96: uint160
    enabled: bool = True
    last_execution: uint = 0
    executions_count: uint = 0

    @property
    def payload(self) -> bytes:
        return abi.encode_packed(
            uint48(self.execute_interval),
            uint16(self.max_executions_count),
            uint48(self.start),
            abi.encode(self.token_in, self.token_out, self.amount_in, self.sqrt_price_limit_x96)
        )


class AllExamplesTest(ExamplesTest):
    beneficiary: Account
    registry: Registry
    registry_attester: Account
    ownable_validator: OwnableValidator
    social_recovery: SocialRecovery
    scheduled_transfers: ScheduledTransfers
    scheduled_orders: ScheduledOrders
    registry_hook: RegistryHook
    ownable_executor: OwnableExecutor
    multifactor: MultiFactor
    deadman_switch: DeadmanSwitch
    hook_multiplexer: HookMultiplexer
    auto_savings: AutoSavings

    # OwnableValidator
    owners: Dict[MSAAdvanced, List[Account]]
    owners_threshold: Dict[MSAAdvanced, uint]

    # SocialRecovery
    guardians: Dict[MSAAdvanced, List[Account]]
    guardians_threshold: Dict[MSAAdvanced, uint]

    # ScheduledTransfers
    transfer_orders: Dict[MSAAdvanced, Dict[uint, TransferOrder]]

    # ScheduledOrders
    swap_orders: Dict[MSAAdvanced, Dict[uint, SwapOrder]]

    # OwnableExecutor
    executor_owners: Dict[MSAAdvanced, List[Account]]

    # MultiFactor
    multifactor_validator_ids: Dict[MSAAdvanced, List[bytes]]
    multifactor_threshold: Dict[MSAAdvanced, uint]
    multifactor_ownable_owners: Dict[MSAAdvanced, Dict[bytes, List[Account]]]
    multifactor_ownable_threshold: Dict[MSAAdvanced, Dict[bytes, uint]]

    # HookMultiplexer
    multiplexer_hooks: Dict[MSAAdvanced, OrderedSet[Account]]

    # AutoSavings
    mock_vaults: Dict[IERC20, MockERC4626]
    auto_saving_tokens: Dict[MSAAdvanced, List[IERC20]]
    auto_saving_configs: Dict[MSAAdvanced, List[AutoSavings.Config]]

    # DeadmanSwitch
    deadman_switch_nominees: Dict[MSAAdvanced, Account]
    deadman_switch_timeouts: Dict[MSAAdvanced, uint]
    deadman_switch_last_accesses: Dict[MSAAdvanced, uint]

    def pre_sequence(self) -> None:
        super().pre_sequence()

        self.owners = {}
        self.owners_threshold = {}

        self.guardians = defaultdict(list)
        self.guardians_threshold = defaultdict(int)

        self.transfer_orders = defaultdict(dict)

        self.swap_orders = defaultdict(dict)

        self.executor_owners = defaultdict(list)

        self.multifactor_validator_ids = defaultdict(list)
        self.multifactor_threshold = defaultdict(int)
        self.multifactor_ownable_owners = {}
        self.multifactor_ownable_threshold = {}

        self.multiplexer_hooks = defaultdict(OrderedSet)

        self.mock_vaults = {
            TOKENS[0]: MockERC4626.deploy(TOKENS[0], "USDC Vault", "USDC"),
            TOKENS[1]: MockERC4626.deploy(TOKENS[1], "USDT Vault", "USDT"),
        }
        self.auto_saving_tokens = defaultdict(list)
        self.auto_saving_configs = defaultdict(list)

        self.deadman_switch_nominees = {}
        self.deadman_switch_timeouts = {}
        self.deadman_switch_last_accesses = {}

        self.beneficiary = Account(1)
        self.registry = Registry.deploy()
        self.ownable_validator = OwnableValidator.deploy()
        self.social_recovery = SocialRecovery.deploy()
        self.scheduled_transfers = ScheduledTransfers.deploy()
        self.scheduled_orders = ScheduledOrders.deploy()
        self.registry_hook = RegistryHook.deploy()
        self.ownable_executor = OwnableExecutor.deploy()
        self.deadman_switch = DeadmanSwitch.deploy()
        self.multifactor = MultiFactor.deploy(IERC7484(self.registry))
        self.hook_multiplexer = HookMultiplexer.deploy(IERC7484(self.registry))
        self.auto_savings = AutoSavings.deploy()

        # registry setup & attestations
        self.registry_attester = random_account()
        schema = self.registry.registerSchema("", IExternalSchemaValidator(Address.ZERO)).return_value
        resolver = self.registry.registerResolver(MockResolver.deploy(self.registry)).return_value
        self.registry.registerModule(resolver, self.registry_hook, b"")
        self.registry.registerModule(resolver, self.ownable_validator, b"")
        self.registry.registerModule(resolver, self.social_recovery, b"")
        self.registry.registerModule(resolver, self.scheduled_transfers, b"")
        self.registry.registerModule(resolver, self.scheduled_orders, b"")
        self.registry.registerModule(resolver, self.ownable_executor, b"")
        self.registry.registerModule(resolver, self.multifactor, b"")
        self.registry.registerModule(resolver, self.deadman_switch, b"")
        self.registry.registerModule(resolver, self.auto_savings, b"")
        self.registry.attest_(
            schema,
            [
                AttestationRequest(self.registry_hook.address, 0, bytearray(b""), [4]),
                AttestationRequest(self.ownable_validator.address, 0, bytearray(b""), [1]),
                AttestationRequest(self.social_recovery.address, 0, bytearray(b""), [1]),
                AttestationRequest(self.scheduled_transfers.address, 0, bytearray(b""), [2]),
                AttestationRequest(self.scheduled_orders.address, 0, bytearray(b""), [2]),
                AttestationRequest(self.ownable_executor.address, 0, bytearray(b""), [2]),
                AttestationRequest(self.multifactor.address, 0, bytearray(b""), [1]),
                AttestationRequest(self.deadman_switch.address, 0, bytearray(b""), [1, 4]),
                AttestationRequest(self.auto_savings.address, 0, bytearray(b""), [2]),
            ],
            from_=self.registry_attester,
        )

        # create first smart account
        self.flow_new_smart_account()

    @staticmethod
    def generate_signature(hash: bytes, owners: List[Account]) -> bytes:
        return b"".join(owner.sign(hash) for owner in owners)

    def execute(self, acc: MSAAdvanced, target: Account, calldata: bytes, value: int = 0) -> Tuple[TransactionAbc, IEntryPoint.UserOperationEvent]:
        if self.multifactor in self.validators[acc] and random_bool():
            # use MultiFactor
            op, hash = self.erc7579_execute_op(
                acc,
                self.multifactor,
                target,
                calldata,
                value
            )

            validators = random.sample(self.multifactor_validator_ids[acc], k=min(self.multifactor_threshold[acc], len(self.multifactor_validator_ids[acc])))
            # generate signature for each OwnableValidator
            v = []
            for validator in validators:
                owners = sorted(random.sample(self.multifactor_ownable_owners[acc][validator], k=min(self.multifactor_ownable_threshold[acc][validator], len(self.multifactor_ownable_owners[acc][validator]))))

                signatures = []
                extra_data = bytearray(b"")
                for owner in owners:
                    if owner in self.smart_accounts:
                        # generate EIP-1271 signature -> use OwnableValidator on smart account
                        # r -> EIP-1271 contract address, s-> offset of additional data in the signature, v -> always 0
                        signatures.append(abi.encode(owner, uint(len(owners) * 65 + len(extra_data))) + b"\x00")
                        assert len(signatures[-1]) == 65
                        hh = keccak256(b"\x19Ethereum Signed Message:\n" + f"{len(hash)}".encode() + hash)
                        tmp = bytes(self.ownable_validator.address) + self.generate_signature(hh, random.sample(self.owners[owner], k=min(self.owners_threshold[owner], len(self.owners[owner]))))
                        extra_data += len(tmp).to_bytes(32, "big") + tmp
                    else:
                        signatures.append(owner.sign(hash))
                v.append(Validator(validator + bytes(self.ownable_validator.address), bytearray(b"".join(signatures) + extra_data)))

            op.signature = bytearray(abi.encode(v))
        else:
            # use OwnableValidator
            op, hash = self.erc7579_execute_op(
                acc,
                self.ownable_validator,
                target,
                calldata,
                value
            )

            op.signature = bytearray(self.generate_signature(hash, random.sample(self.owners[acc], k=min(self.owners_threshold[acc], len(self.owners[acc])))))

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        if e.success:
            self.deadman_switch_last_accesses[acc] = tx.block.timestamp

        return tx, e

    def add_global_hook(self, acc: MSAAdvanced, hook: TrustedForwarder) -> None:
        if len(self.multiplexer_hooks[acc]) == 0:
            # must be uninstalled first
            if self.hooks.get(acc, None) == self.hook_multiplexer:
                tx, e = self.execute(
                    acc,
                    acc,
                    abi.encode_call(acc.uninstallModule, [4, self.hook_multiplexer, b""]),
                )
                assert e.success

            tx, e = self.execute(
                acc,
                acc,
                abi.encode_call(acc.installModule, [4, self.hook_multiplexer, abi.encode([hook], [], [], [], [])]),
            )
            assert e.success

            self.hooks[acc] = self.hook_multiplexer
        else:
            tx, e = self.execute(
                acc,
                self.hook_multiplexer,
                abi.encode_call(self.hook_multiplexer.addHook, [hook, HookType.GLOBAL]),
            )
            assert e.success

        # needed with hook multiplexer
        tx, e = self.execute(
            acc,
            hook,
            abi.encode_call(hook.setTrustedForwarder, [self.hook_multiplexer]),
        )
        assert e.success

    def new_transfer_order(self) -> TransferOrder:
        return TransferOrder(
            execute_interval=random_int(1, 10),
            max_executions_count=random_int(1, 10),
            start=chain.blocks["pending"].timestamp + random_int(1, 10),
            recipient=random_account(),
            token=random.choice(TOKENS + [IERC20(Address.ZERO)]),
            amount=uint(random_int(1, 1000)),
        )

    def new_swap_order(self) -> SwapOrder:
        if random_bool():
            token_in = IERC20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")  # usdc
            token_out = IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7")  # usdt
        else:
            token_in = IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7")  # usdt
            token_out = IERC20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48") # usdc

        return SwapOrder(
            execute_interval=random_int(1, 10),
            max_executions_count=random_int(1, 10),
            start=chain.blocks["pending"].timestamp + random_int(1, 10),
            token_in=token_in,
            token_out=token_out,
            amount_in=uint(random_int(1, 10) * 10**token_in.decimals()),
            sqrt_price_limit_x96=uint160(0),
        )

    @flow(max_times=10)
    def flow_new_smart_account(self) -> None:
        # use OwnableValidator as the initial validator
        owners = sorted(random.sample(chain.accounts, random_int(1, len(chain.accounts))), reverse=True)
        threshold = uint(random_int(1, len(owners)))

        acc = self.new_smart_account(self.ownable_validator, abi.encode(threshold, list(reversed(owners))))

        self.owners[acc] = owners
        self.owners_threshold[acc] = threshold

        # configure trusted attester in registry
        tx, e = self.execute(
            acc,
            self.registry,
            abi.encode_call(self.registry.trustAttesters, [uint8(1), [self.registry_attester]])
        )
        assert e.success

        logger.info(f"New smart account: {acc}")

    @flow()
    def flow_add_owner(self) -> None:
        acc = random.choice(self.smart_accounts)
        owner = random_account()

        tx, e = self.execute(
            acc,
            self.ownable_validator,
            abi.encode_call(self.ownable_validator.addOwner, [owner]),
        )

        if self.ownable_validator not in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.NotInitialized(acc.address))
        elif owner in self.owners[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(owner.address))
        else:
            assert e.success
            self.owners[acc].insert(0, owner)

            logger.info(f"Added owner {owner} to {acc}")

    @flow()
    def flow_remove_owner(self) -> None:
        acc = random.choice(self.smart_accounts)
        if len(self.owners[acc]) == self.owners_threshold[acc]:
            return

        owner = random_account()

        if owner not in self.owners[acc]:
            prev_owner = Account(1)
        else:
            index = self.owners[acc].index(owner)
            if index == 0:
                prev_owner = Account(1)
            else:
                prev_owner = self.owners[acc][index - 1]

        tx, e = self.execute(
            acc,
            self.ownable_validator,
            abi.encode_call(self.ownable_validator.removeOwner, [prev_owner, owner]),
        )

        if self.ownable_validator not in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.NotInitialized(acc.address))
        elif owner not in self.owners[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_InvalidEntry(owner.address))
        else:
            assert e.success
            self.owners[acc].remove(owner)

            logger.info(f"Removed owner {owner} from {acc}")

    @flow()
    def flow_set_ownable_threshold(self) -> None:
        acc = random.choice(self.smart_accounts)
        threshold = random_int(0, len(self.owners[acc]) + 1)

        tx, e = self.execute(
            acc,
            self.ownable_validator,
            abi.encode_call(self.ownable_validator.setThreshold, [uint(threshold)]),
        )

        if self.ownable_validator not in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.NotInitialized(acc.address))
        elif threshold == 0 or threshold > len(self.owners[acc]):
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SocialRecovery.InvalidThreshold())
        else:
            assert e.success

            self.owners_threshold[acc] = threshold

            logger.info(f"Set OwnableValidator threshold to {threshold} for {acc}")

    @flow()
    def flow_install_social_recovery(self) -> None:
        acc = random.choice(self.smart_accounts)
        guardians = sorted(random.sample(chain.accounts, random_int(1, len(chain.accounts))), reverse=True)
        threshold = uint(random_int(1, len(guardians)))

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.installModule, [1, self.social_recovery, abi.encode(threshold, list(reversed(guardians)))]),
        )

        if self.social_recovery in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(self.social_recovery.address))
        else:
            assert e.success

            self.validators[acc].insert(0, self.social_recovery)
            self.guardians[acc] = guardians
            self.guardians_threshold[acc] = threshold

            logger.info(f"Installed SocialRecovery to {acc}")

    @flow()
    def flow_uninstall_social_recovery(self) -> None:
        accounts = [a for a in self.smart_accounts if self.social_recovery in self.validators[a]]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)
        index = self.validators[acc].index(self.social_recovery)
        if index == 0:
            prev_validator = Account(1)
        else:
            prev_validator = self.validators[acc][index - 1]

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.uninstallModule, [1, self.social_recovery, abi.encode(prev_validator, b"")]),
        )
        assert e.success

        del self.validators[acc][index]

        logger.info(f"Uninstalled SocialRecovery from {acc}")

    @flow()
    def flow_set_social_recovery_threshold(self):
        acc = random.choice(self.smart_accounts)
        threshold = random_int(0, len(self.guardians[acc]) + 1)

        tx, e = self.execute(
            acc,
            self.social_recovery,
            abi.encode_call(self.social_recovery.setThreshold, [uint(threshold)]),
        )

        if self.social_recovery not in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SocialRecovery.NotInitialized(acc.address))
        elif threshold == 0 or threshold > len(self.guardians[acc]):
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SocialRecovery.InvalidThreshold())
        else:
            assert e.success

            self.guardians_threshold[acc] = threshold

            logger.info(f"Set SocialRecovery threshold to {threshold} for {acc}")

    @flow()
    def flow_add_guardian(self):
        acc = random.choice(self.smart_accounts)
        guardian = random_account()

        tx, e = self.execute(
            acc,
            self.social_recovery,
            abi.encode_call(self.social_recovery.addGuardian, [guardian]),
        )

        if self.social_recovery not in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.NotInitialized(acc.address))
        elif guardian in self.guardians[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(guardian.address))
        else:
            assert e.success
            self.guardians[acc].insert(0, guardian)

            logger.info(f"Added guardian {guardian} to {acc}")

    @flow()
    def flow_remove_guardian(self):
        acc = random.choice(self.smart_accounts)
        if len(self.guardians[acc]) == self.guardians_threshold[acc]:
            return

        guardian = random_account()

        if guardian not in self.guardians[acc]:
            prev_guardian = Account(1)
        else:
            index = self.guardians[acc].index(guardian)
            if index == 0:
                prev_guardian = Account(1)
            else:
                prev_guardian = self.guardians[acc][index - 1]

        tx, e = self.execute(
            acc,
            self.social_recovery,
            abi.encode_call(self.social_recovery.removeGuardian, [prev_guardian, guardian]),
        )

        if self.social_recovery not in self.validators[acc]:
            # does not evert with NotInitialized
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_InvalidEntry(guardian.address))
        elif guardian not in self.guardians[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_InvalidEntry(guardian.address))
        else:
            assert e.success
            self.guardians[acc].remove(guardian)

            logger.info(f"Removed guardian {guardian} from {acc}")

    @flow()
    def flow_install_scheduled_transfers(self) -> None:
        acc = random.choice(self.smart_accounts)
        order = self.new_transfer_order()

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.installModule, [2, self.scheduled_transfers, order.payload]),
        )

        if self.scheduled_transfers in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(self.scheduled_transfers.address))
        else:
            assert e.success

            e = next(e for e in tx.events if isinstance(e, ScheduledTransfers.ExecutionAdded))
            self.executors[acc].insert(0, self.scheduled_transfers)
            self.transfer_orders[acc] = {e.jobId: order}

            logger.info(f"Installed ScheduledTransfers to {acc}")
            logger.info(f"Added transfer order {e.jobId} to {acc}: {order}")

    @flow()
    def flow_uninstall_scheduled_transfers(self) -> None:
        accounts = [a for a in self.smart_accounts if self.scheduled_transfers in self.executors[a]]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)
        index = self.executors[acc].index(self.scheduled_transfers)
        if index == 0:
            prev_executor = Account(1)
        else:
            prev_executor = self.executors[acc][index - 1]

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.uninstallModule, [2, self.scheduled_transfers, abi.encode(prev_executor, b"")]),
        )
        assert e.success

        del self.executors[acc][index]

        logger.info(f"Uninstalled ScheduledTransfers from {acc}")

    @flow()
    def flow_add_transfer_order(self) -> None:
        acc = random.choice(self.smart_accounts)
        order = self.new_transfer_order()

        tx, e = self.execute(
            acc,
            self.scheduled_transfers,
            abi.encode_call(self.scheduled_transfers.addOrder, [order.payload]),
        )

        if self.scheduled_transfers in self.executors[acc]:
            assert e.success

            e = next(e for e in tx.events if isinstance(e, ScheduledTransfers.ExecutionAdded))
            self.transfer_orders[acc][e.jobId] = order

            logger.info(f"Added transfer order {e.jobId} to {acc}: {order}")
        else:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.NotInitialized(acc.address))

            self.transfer_orders[acc].clear()

    @flow()
    def flow_toggle_transfer_order(self) -> None:
        acc = random.choice(self.smart_accounts)
        orders = self.transfer_orders[acc]

        if len(orders) == 0:
            return

        job_id, order = random.choice(list(orders.items()))

        tx, e = self.execute(
            acc,
            self.scheduled_transfers,
            abi.encode_call(self.scheduled_transfers.toggleOrder, [job_id]),
        )

        if self.scheduled_transfers in self.executors[acc]:
            assert e.success

            order.enabled = not order.enabled

            logger.info(f"Toggled transfer order {job_id} of {acc}")
        else:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.InvalidExecution())

            self.transfer_orders[acc].clear()

    @flow()
    def flow_execute_scheduled_transfer(self) -> None:
        acc = random.choice(self.smart_accounts)
        orders = self.transfer_orders[acc]

        if len(orders) == 0:
            return

        job_id, order = random.choice(list(orders.items()))

        if order.token == Account(0):
            acc_before = acc.balance
            recipient_before = order.recipient.balance

            acc.balance += order.amount
        else:
            acc_before = order.token.balanceOf(acc)
            recipient_before = order.token.balanceOf(order.recipient)

            mint_erc20(order.token, acc, order.amount)

        tx, e = self.execute(
            acc,
            self.scheduled_transfers,
            abi.encode_call(self.scheduled_transfers.executeOrder, [job_id]),
        )

        if self.scheduled_transfers not in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.InvalidExecution())

            self.transfer_orders[acc].clear()
        elif not order.enabled:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.InvalidExecution())
        elif order.last_execution + order.execute_interval > tx.block.timestamp:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.InvalidExecution())
        elif order.executions_count >= order.max_executions_count:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.InvalidExecution())

            # remove the order
            del self.transfer_orders[acc][job_id]
        elif order.start > tx.block.timestamp:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.InvalidExecution())
        else:
            assert e.success

            if order.token == Account(0):
                assert acc.balance == acc_before
                assert order.recipient.balance == recipient_before + order.amount
            else:
                assert order.token.balanceOf(acc) == acc_before
                assert order.token.balanceOf(order.recipient) == recipient_before + order.amount

            order.last_execution = tx.block.timestamp
            order.executions_count += 1

            logger.info(f"Executed transfer order {job_id}: {order}")

    @flow()
    def flow_install_scheduled_orders(self) -> None:
        acc = random.choice(self.smart_accounts)
        order = self.new_swap_order()

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.installModule, [2, self.scheduled_orders, order.payload]),
        )

        if self.scheduled_orders in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(self.scheduled_orders.address))
        else:
            assert e.success

            e = next(e for e in tx.events if isinstance(e, ScheduledOrders.ExecutionAdded))
            self.executors[acc].insert(0, self.scheduled_orders)
            self.swap_orders[acc] = {e.jobId: order}

            logger.info(f"Installed ScheduledOrders to {acc}")
            logger.info(f"Added swap order {e.jobId} to {acc}: {order}")

    @flow()
    def flow_uninstall_scheduled_orders(self) -> None:
        accounts = [a for a in self.smart_accounts if self.scheduled_orders in self.executors[a]]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)
        index = self.executors[acc].index(self.scheduled_orders)
        if index == 0:
            prev_executor = Account(1)
        else:
            prev_executor = self.executors[acc][index - 1]

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.uninstallModule, [2, self.scheduled_orders, abi.encode(prev_executor, b"")]),
        )
        assert e.success

        del self.executors[acc][index]

        logger.info(f"Uninstalled ScheduledOrders from {acc}")

    @flow()
    def flow_add_swap_order(self) -> None:
        acc = random.choice(self.smart_accounts)
        order = self.new_swap_order()

        tx, e = self.execute(
            acc,
            self.scheduled_orders,
            abi.encode_call(self.scheduled_orders.addOrder, [order.payload]),
        )

        if self.scheduled_orders in self.executors[acc]:
            assert e.success

            e = next(e for e in tx.events if isinstance(e, ScheduledOrders.ExecutionAdded))
            self.swap_orders[acc][e.jobId] = order

            logger.info(f"Added swap order {e.jobId} to {acc}: {order}")
        else:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledOrders.NotInitialized(acc.address))

            self.swap_orders[acc].clear()

    @flow()
    def flow_toggle_swap_order(self) -> None:
        acc = random.choice(self.smart_accounts)
        orders = self.swap_orders[acc]

        if len(orders) == 0:
            return

        job_id, order = random.choice(list(orders.items()))

        tx, e = self.execute(
            acc,
            self.scheduled_orders,
            abi.encode_call(self.scheduled_orders.toggleOrder, [job_id]),
        )

        if self.scheduled_orders in self.executors[acc]:
            assert e.success

            order.enabled = not order.enabled

            logger.info(f"Toggled swap order {job_id} of {acc}")
        else:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledOrders.InvalidExecution())

            self.swap_orders[acc].clear()

    @flow()
    def flow_execute_scheduled_swap(self) -> None:
        acc = random.choice(self.smart_accounts)
        orders = self.swap_orders[acc]

        if len(orders) == 0:
            return

        job_id, order = random.choice(list(orders.items()))

        mint_erc20(order.token_in, acc, order.amount_in)

        in_before = order.token_in.balanceOf(acc)
        out_before = order.token_out.balanceOf(acc)

        tx, e = self.execute(
            acc,
            self.scheduled_orders,
            abi.encode_call(self.scheduled_orders.executeOrder, [job_id]),
        )

        if self.scheduled_orders not in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledOrders.InvalidExecution())

            self.swap_orders[acc].clear()
        elif not order.enabled:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledOrders.InvalidExecution())
        elif order.last_execution + order.execute_interval > tx.block.timestamp:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledOrders.InvalidExecution())
        elif order.executions_count >= order.max_executions_count:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledOrders.InvalidExecution())

            # remove the order
            del self.swap_orders[acc][job_id]
        elif order.start > tx.block.timestamp:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledOrders.InvalidExecution())
        else:
            assert e.success

            assert order.token_in.balanceOf(acc) < in_before
            assert order.token_out.balanceOf(acc) > out_before

            order.last_execution = tx.block.timestamp
            order.executions_count += 1

            logger.info(f"Executed swap order {job_id}: {order}")

    @flow()
    def flow_install_registry_hook(self):
        acc = random.choice(self.smart_accounts)

        if self.registry_hook in self.multiplexer_hooks[acc]:
            # already installed, contract does not revert by design
            return

        self.add_global_hook(acc, self.registry_hook)

        tx, e = self.execute(
            acc,
            self.registry_hook,
            abi.encode_call(self.registry_hook.onInstall, [bytes(self.registry.address)]),
        )
        assert e.success

        self.multiplexer_hooks[acc].add(self.registry_hook)

        logger.info(f"Installed RegistryHook to {acc}")

    @flow()
    def flow_uninstall_registry_hook(self):
        accounts = [a for a in self.smart_accounts if self.registry_hook == self.hooks.get(a, None)]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)

        tx, e = self.execute(
            acc,
            self.hook_multiplexer,
            abi.encode_call(self.hook_multiplexer.removeHook, [self.registry_hook, HookType.GLOBAL]),
        )
        assert e.success
        self.multiplexer_hooks[acc].remove(self.registry_hook)

        logger.info(f"Uninstalled RegistryHook from {acc}")

    @flow()
    def flow_install_ownable_executor(self):
        acc = random.choice(self.smart_accounts)
        owner = random.choice(list(chain.accounts) + self.smart_accounts)

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.installModule, [2, self.ownable_executor, bytes(owner.address)]),
        )

        if self.ownable_executor in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(self.ownable_executor.address))
        else:
            assert e.success

            self.executors[acc].insert(0, self.ownable_executor)
            self.executor_owners[acc] = [owner]

            logger.info(f"Installed OwnableExecutor to {acc}")
            logger.info(f"Added owner {owner} to OwnableExecutor of {acc}")

    @flow()
    def flow_uninstall_ownable_executor(self):
        accounts = [a for a in self.smart_accounts if self.ownable_executor in self.executors[a]]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)
        index = self.executors[acc].index(self.ownable_executor)
        if index == 0:
            prev_executor = Account(1)
        else:
            prev_executor = self.executors[acc][index - 1]

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.uninstallModule, [2, self.ownable_executor, abi.encode(prev_executor, b"")]),
        )
        assert e.success

        del self.executors[acc][index]

        logger.info(f"Uninstalled OwnableExecutor from {acc}")

    @flow()
    def flow_add_ownable_executor_owner(self):
        acc = random.choice(self.smart_accounts)
        owner = random.choice(list(chain.accounts) + self.smart_accounts)

        tx, e = self.execute(
            acc,
            self.ownable_executor,
            abi.encode_call(self.ownable_executor.addOwner, [owner]),
        )

        if self.ownable_executor not in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(OwnableExecutor.NotInitialized(acc.address))
        elif owner in self.executor_owners[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(owner.address))
        else:
            assert e.success
            self.executor_owners[acc].insert(0, owner)

            logger.info(f"Added owner {owner} to OwnableExecutor of {acc}")

    @flow()
    def flow_remove_ownable_executor_owner(self):
        acc = random.choice(self.smart_accounts)
        owner = random.choice(list(chain.accounts) + self.smart_accounts)

        if owner not in self.executor_owners[acc]:
            prev_owner = Account(1)
        else:
            index = self.executor_owners[acc].index(owner)
            if index == 0:
                prev_owner = Account(1)
            else:
                prev_owner = self.executor_owners[acc][index - 1]

        tx, e = self.execute(
            acc,
            self.ownable_executor,
            abi.encode_call(self.ownable_executor.removeOwner, [prev_owner, owner]),
        )

        if self.ownable_executor not in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_InvalidEntry(owner.address))
        elif owner not in self.executor_owners[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_InvalidEntry(owner.address))
        else:
            assert e.success
            self.executor_owners[acc].remove(owner)

            logger.info(f"Removed owner {owner} from OwnableExecutor of {acc}")

    @flow()
    def flow_execute_on_owned_account(self):
        acc = random.choice(self.smart_accounts)
        if len(self.executor_owners[acc]) == 0:
            return

        owner = random.choice(self.executor_owners[acc])
        recipient = Account(random_address())
        value = random_int(0, 1000, edge_values_prob=0.3)
        payload = abi.encode_packed(recipient, uint(value), b"")

        owner.balance += value
        owner_before = owner.balance
        recipient_before = recipient.balance

        if isinstance(owner, MSAAdvanced):
            tx, e = self.execute(
                owner,
                self.ownable_executor,
                abi.encode_call(self.ownable_executor.executeOnOwnedAccount, [acc, payload]),
                value=value,
            )

            if self.ownable_executor not in self.executors[acc]:
                assert not e.success
                reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
                assert reason.revertReason == abi.encode(OwnableExecutor.UnauthorizedAccess())
            else:
                assert e.success

                assert owner.balance == owner_before - value
                assert recipient.balance == recipient_before + value

                self.deadman_switch_last_accesses[acc] = tx.block.timestamp

                logger.info(f"Executed on owned account {acc} by {owner}")
        else:
            with may_revert(OwnableExecutor.UnauthorizedAccess) as exc:
                tx = self.ownable_executor.executeOnOwnedAccount(acc, payload, from_=owner, value=value)

            if self.ownable_executor not in self.executors[acc]:
                assert exc.value == OwnableExecutor.UnauthorizedAccess()
            else:
                assert exc.value is None

                assert owner.balance == owner_before - value
                assert recipient.balance == recipient_before + value

                self.deadman_switch_last_accesses[acc] = tx.block.timestamp

                logger.info(f"Executed on owned account {acc} by {owner}")

    @flow()
    def flow_execute_batch_on_owned_account(self):
        acc = random.choice(self.smart_accounts)
        if len(self.executor_owners[acc]) == 0:
            return

        owner = random.choice(self.executor_owners[acc])
        recipients = [Account(random_address()) for _ in range(random_int(0, 10))]
        values = [random_int(0, 1000, edge_values_prob=0.15) for _ in range(len(recipients))]
        payload = abi.encode([Execution(recipient.address, uint(value), bytearray(b"")) for recipient, value in zip(recipients, values)])

        owner.balance += sum(values)
        owner_before = owner.balance
        recipients_before = [recipient.balance for recipient in recipients]

        if isinstance(owner, MSAAdvanced):
            tx, e = self.execute(
                owner,
                self.ownable_executor,
                abi.encode_call(self.ownable_executor.executeBatchOnOwnedAccount, [acc, payload]),
                value=sum(values),
            )

            if self.ownable_executor not in self.executors[acc]:
                assert not e.success
                reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
                assert reason.revertReason == abi.encode(OwnableExecutor.UnauthorizedAccess())
            else:
                assert e.success

                assert owner.balance == owner_before - sum(values)
                # assuming no duplicates in recipients
                for recipient, value, before in zip(recipients, values, recipients_before):
                    assert recipient.balance == before + value

                self.deadman_switch_last_accesses[acc] = tx.block.timestamp

                logger.info(f"Executed batch on owned account {acc} by {owner}")
        else:
            with may_revert(OwnableExecutor.UnauthorizedAccess) as exc:
                tx = self.ownable_executor.executeBatchOnOwnedAccount(acc, payload, from_=owner, value=sum(values))

            if self.ownable_executor not in self.executors[acc]:
                assert exc.value == OwnableExecutor.UnauthorizedAccess()
            else:
                assert exc.value is None

                assert owner.balance == owner_before - sum(values)
                # assuming no duplicates in recipients
                for recipient, value, before in zip(recipients, values, recipients_before):
                    assert recipient.balance == before + value

                self.deadman_switch_last_accesses[acc] = tx.block.timestamp

                logger.info(f"Executed batch on owned account {acc} by {owner}")

    @flow()
    def flow_install_multifactor(self):
        acc = random.choice(self.smart_accounts)
        validators = random.choices([self.ownable_validator], k=random_int(1, 3))
        ids = [bytes(random_bytes(12)) for _ in range(len(validators))]
        owners = [sorted(random.sample(list(chain.accounts) + self.smart_accounts, k=random_int(1, 10))) for _ in range(len(validators))]
        thresholds = [uint(random_int(1, len(o))) for o in owners]
        threshold = uint8(random_int(1, len(validators)))
        payload = threshold.to_bytes(1) + abi.encode([Validator(id + bytes(v.address), bytearray(abi.encode(t, o))) for v, id, o, t in zip(validators, ids, owners, thresholds)])

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.installModule, [1, self.multifactor, payload]),
        )

        if self.multifactor in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(self.multifactor.address))
        else:
            assert e.success

            self.validators[acc].insert(0, self.multifactor)
            self.multifactor_validator_ids[acc] = ids
            self.multifactor_threshold[acc] = uint(threshold)

            self.multifactor_ownable_owners[acc] = {}
            self.multifactor_ownable_threshold[acc] = {}
            for id, o, t in zip(ids, owners, thresholds):
                self.multifactor_ownable_owners[acc][id] = o
                self.multifactor_ownable_threshold[acc][id] = t

            logger.info(f"Installed Multifactor to {acc}")

    @flow()
    def flow_uninstall_multifactor(self):
        accounts = [a for a in self.smart_accounts if self.multifactor in self.validators[a]]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)
        index = self.validators[acc].index(self.multifactor)
        if index == 0:
            prev_validator = Account(1)
        else:
            prev_validator = self.validators[acc][index - 1]

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.uninstallModule, [1, self.multifactor, abi.encode(prev_validator, b"")]),
        )
        assert e.success

        del self.validators[acc][index]
        del self.multifactor_ownable_owners[acc]
        del self.multifactor_ownable_threshold[acc]

        logger.info(f"Uninstalled Multifactor from {acc}")

    @flow()
    def flow_multifactor_set_threshold(self):
        acc = random.choice(self.smart_accounts)
        threshold = uint8(random_int(0, len(self.multifactor_validator_ids[acc])))

        tx, e = self.execute(
            acc,
            self.multifactor,
            abi.encode_call(self.multifactor.setThreshold, [threshold]),
        )

        if self.multifactor not in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(MultiFactor.NotInitialized(acc.address))
        elif threshold == 0 or threshold > len(self.multifactor_validator_ids[acc]):
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(MultiFactor.ZeroThreshold())
        else:
            assert e.success

            self.multifactor_threshold[acc] = threshold

            logger.info(f"Set Multifactor threshold to {threshold} for {acc}")

    @flow()
    def flow_multifactor_set_validator(self):
        acc = random.choice(self.smart_accounts)

        if len(self.multifactor_validator_ids[acc]) == 0 or random.random() < 0.3:
            id = bytes(random_bytes(12))
        else:
            id = random.choice(self.multifactor_validator_ids[acc])

        owners = sorted(random.sample(list(chain.accounts) + self.smart_accounts, k=random_int(1, 10)))
        threshold = uint(random_int(1, len(owners)))

        tx, e = self.execute(
            acc,
            self.multifactor,
            abi.encode_call(self.multifactor.setValidator, [self.ownable_validator, id, abi.encode(threshold, owners)]),
        )

        if self.multifactor not in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(MultiFactor.NotInitialized(acc.address))
        else:
            assert e.success

            if id not in self.multifactor_validator_ids[acc]:
                self.multifactor_validator_ids[acc].append(id)

            self.multifactor_ownable_owners[acc][id] = owners
            self.multifactor_ownable_threshold[acc][id] = threshold

            logger.info(f"Set Multifactor validator {id} for {acc}")

    @flow()
    def flow_multifactor_remove_validator(self):
        acc = random.choice(self.smart_accounts)

        if len(self.multifactor_validator_ids[acc]) == self.multifactor_threshold[acc]:
            return

        if len(self.multifactor_validator_ids[acc]) == 0:
            id = bytes(random_bytes(12))
        else:
            id = random.choice(self.multifactor_validator_ids[acc])

        tx, e = self.execute(
            acc,
            self.multifactor,
            abi.encode_call(self.multifactor.removeValidator, [self.ownable_validator, id]),
        )

        if self.multifactor not in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(MultiFactor.NotInitialized(acc.address))
        else:
            assert e.success

            if id in self.multifactor_validator_ids[acc]:
                self.multifactor_validator_ids[acc].remove(id)
                del self.multifactor_ownable_owners[acc][id]
                del self.multifactor_ownable_threshold[acc][id]

            logger.info(f"Removed Multifactor validator {id} from {acc}")

    @flow()
    def flow_install_auto_savings(self):
        acc = random.choice(self.smart_accounts)

        tokens = random.sample([TOKENS[0], TOKENS[1]], random_int(1, 2))
        configs = []
        for _ in range(len(tokens)):
            configs.append(AutoSavings.Config(
                random_int(0, 100),
                random.choice(list(self.mock_vaults.values())).address,
                0,
            ))

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.installModule, [2, self.auto_savings, abi.encode(tokens, configs)]),
        )

        if self.auto_savings in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(self.auto_savings.address))
        else:
            assert e.success

            self.executors[acc].insert(0, self.auto_savings)
            self.auto_saving_tokens[acc] = list(reversed(tokens))
            self.auto_saving_configs[acc] = list(reversed(configs))

            logger.info(f"Installed AutoSavings to {acc}")

    @flow()
    def flow_uninstall_auto_savings(self):
        accounts = [a for a in self.smart_accounts if self.auto_savings in self.executors[a]]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)
        index = self.executors[acc].index(self.auto_savings)
        if index == 0:
            prev_executor = Account(1)
        else:
            prev_executor = self.executors[acc][index - 1]

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.uninstallModule, [2, self.auto_savings, abi.encode(prev_executor, b"")]),
        )
        assert e.success

        del self.executors[acc][index]
        del self.auto_saving_configs[acc]

        logger.info(f"Uninstalled AutoSavings from {acc}")

    @flow()
    def flow_auto_savings_set_config(self):
        acc = random.choice(self.smart_accounts)

        if len(self.auto_saving_configs[acc]) == 0:
            return

        token = random.choice([TOKENS[0], TOKENS[1]])
        config = AutoSavings.Config(
            random_int(0, 100),
            random.choice(list(self.mock_vaults.values())).address,
            0,
        )

        tx, e = self.execute(
            acc,
            self.auto_savings,
            abi.encode_call(self.auto_savings.setConfig, [token, config]),
        )

        if self.auto_savings not in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(AutoSavings.NotInitialized(acc.address))
        else:
            assert e.success

            if token not in self.auto_saving_tokens[acc]:
                self.auto_saving_tokens[acc].insert(0, token)
                self.auto_saving_configs[acc].insert(0, config)
            else:
                index = self.auto_saving_tokens[acc].index(token)
                self.auto_saving_configs[acc][index] = config

            logger.info(f"Set AutoSavings config for {token} to {config} for {acc}")

    @flow()
    def flow_auto_savings_delete_config(self):
        acc = random.choice(self.smart_accounts)

        if len(self.auto_saving_configs[acc]) == 0:
            return

        token = random.choice(self.auto_saving_tokens[acc])
        index = self.auto_saving_tokens[acc].index(token)
        if index == 0:
            prev_token = Account(1)
        else:
            prev_token = self.auto_saving_tokens[acc][index - 1]

        tx, e = self.execute(
            acc,
            self.auto_savings,
            abi.encode_call(self.auto_savings.deleteConfig, [prev_token, token]),
        )

        if self.auto_savings not in self.executors[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(AutoSavings.NotInitialized(acc.address))
        else:
            assert e.success

            del self.auto_saving_tokens[acc][index]
            del self.auto_saving_configs[acc][index]

            logger.info(f"Deleted AutoSavings config for {token} from {acc}")

    @flow()
    def flow_auto_savings_auto_save(self):
        accounts = [a for a in self.smart_accounts if self.auto_savings in self.executors[a] and len(self.auto_saving_tokens[a]) > 0]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)
        token = random.choice(self.auto_saving_tokens[acc])
        config = self.auto_saving_configs[acc][self.auto_saving_tokens[acc].index(token)]
        amount = random_int(1, 10) * 10 ** token.decimals()
        vault = MockERC4626(config.vault)

        mint_erc20(token, acc, amount)
        acc_before = token.balanceOf(acc)
        vault_before = vault.balanceOf(acc)

        tx, e = self.execute(
            acc,
            self.auto_savings,
            abi.encode_call(self.auto_savings.autoSave, [token, amount]),
        )
        if not e.success:
            e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            if e.revertReason == abi.encode(Error("AS")):
                assert amount * config.percentage // 100 == 0
            else:
                assert e.revertReason == abi.encode(Error("ZERO_SHARES"))
            return

        assert token.balanceOf(acc) == acc_before - amount * config.percentage // 100
        # performs UniSwap swap, so the amount may be different
        assert vault.balanceOf(acc) > vault_before

        logger.info(f"Auto-saved {amount} {token} to {vault} for {acc}")

    @flow()
    def flow_install_deadman_switch(self):
        acc = random.choice(self.smart_accounts)
        nominee = random.choice(list(chain.accounts) + self.smart_accounts)
        timeout = random_int(1, 20)

        # install as validator
        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.installModule, [1, self.deadman_switch, abi.encode_packed(nominee, uint48(timeout))]),
        )

        if self.deadman_switch in self.validators[acc]:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(SentinelList4337Lib.LinkedList_EntryAlreadyInList(self.deadman_switch.address))
            return

        assert e.success

        self.add_global_hook(acc, self.deadman_switch)

        tx, e = self.execute(
            acc,
            self.deadman_switch,
            abi.encode_call(self.deadman_switch.onInstall, [b""]),
        )
        assert e.success

        self.validators[acc].insert(0, self.deadman_switch)
        self.multiplexer_hooks[acc].add(self.deadman_switch)
        self.deadman_switch_nominees[acc] = nominee
        self.deadman_switch_timeouts[acc] = timeout
        self.deadman_switch_last_accesses[acc] = tx.block.timestamp

        logger.info(f"Installed DeadmanSwitch to {acc}")

    @flow()
    def flow_uninstall_deadman_switch(self):
        accounts = [a for a in self.smart_accounts if self.deadman_switch in self.validators[a]]
        if len(accounts) == 0:
            return

        acc = random.choice(accounts)

        tx, e = self.execute(
            acc,
            self.hook_multiplexer,
            abi.encode_call(self.hook_multiplexer.removeHook, [self.deadman_switch, HookType.GLOBAL]),
        )
        assert e.success
        self.multiplexer_hooks[acc].remove(self.deadman_switch)

        index = self.validators[acc].index(self.deadman_switch)
        if index == 0:
            prev_validator = Account(1)
        else:
            prev_validator = self.validators[acc][index - 1]

        tx, e = self.execute(
            acc,
            acc,
            abi.encode_call(acc.uninstallModule, [1, self.deadman_switch, abi.encode(prev_validator, b"")]),
        )
        assert e.success

        self.validators[acc].remove(self.deadman_switch)

        logger.info(f"Uninstalled DeadmanSwitch from {acc}")

    @flow()
    def flow_deadman_switch_recover(self):
        accounts = [a for a in self.smart_accounts if self.deadman_switch in self.validators[a]]

        if len(accounts) == 0:
            return

        acc = random.choice(accounts)
        nominee = self.deadman_switch_nominees[acc]
        value = random_int(1, 1000)

        acc.balance += value
        acc_before = acc.balance
        nominee_before = nominee.balance

        op, hash = self.erc7579_execute_op(
            acc,
            self.deadman_switch,
            nominee,
            b"",
            value
        )

        if nominee in self.smart_accounts:
            # generate EIP-1271 signature
            hh = keccak256(b"\x19Ethereum Signed Message:\n" + f"{len(hash)}".encode() + hash)
            op.signature = bytearray(bytes(self.ownable_validator.address) + self.generate_signature(hh, random.sample(self.owners[nominee], k=min(self.owners_threshold[nominee], len(self.owners[nominee])))))
        else:
            op.signature = bytearray(nominee.sign(hash))

        timestamp = chain.blocks["pending"].timestamp

        with may_revert() as exc:
            tx = ENTRY_POINY.handleOps([op], self.beneficiary)
            e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        if timestamp < self.deadman_switch_last_accesses[acc] + self.deadman_switch_timeouts[acc]:
            assert exc.value.tx.raw_error.data == abi.encode(EntryPoint.FailedOp(0, "AA22 expired or not due"))
            # fix nonce due to reverted operation
            self.nonces[acc][self.deadman_switch] -= 1
        else:
            assert e.success

            if acc != nominee:
                assert acc.balance == acc_before - value
                assert nominee.balance == nominee_before + value
            else:
                assert acc.balance == acc_before
                assert nominee.balance == nominee_before

            self.deadman_switch_last_accesses[acc] = timestamp

            logger.info(f"Recovered {value} from {acc} by {nominee}")


@chain.connect(fork="http://localhost:8545")
@on_revert(lambda e: print(e.tx.call_trace if e.tx else "Call reverted"))
def test_all_examples() -> None:
    AllExamplesTest().run(10, 1000)
