import logging
from dataclasses import dataclass
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.interfaces.IEntryPoint import IEntryPoint
from pytypes.source.examples.src.ScheduledTransfers.ScheduledTransfers import ScheduledTransfers
from pytypes.source.examples.node_modules.forgestd.src.interfaces.IERC20 import IERC20

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
class Order:
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
        return abi.encode_packed(uint48(self.execute_interval), uint16(self.max_executions_count), uint48(self.start), abi.encode(self.recipient, self.token, self.amount))


class ScheduledTransfersTest(ExamplesTest):
    beneficiary: Account
    scheduled_transfers: ScheduledTransfers
    acc: MSAAdvanced

    orders: Dict[uint, Order]

    def pre_sequence(self) -> None:
        super().pre_sequence()

        self.orders = {}
        self.beneficiary = Account(1)
        self.scheduled_transfers = ScheduledTransfers.deploy()
        self.acc = self.new_smart_account()

        order = self.new_random_order()

        op, _ = self.user_op(
            self.acc,
            self.simple_validator,
            abi.encode_call(self.acc.installModule, [2, self.scheduled_transfers, order.payload]),
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        self.executors[self.acc].insert(0, self.scheduled_transfers)

        e = next(e for e in tx.events if isinstance(e, ScheduledTransfers.ExecutionAdded))
        self.orders[e.jobId] = order

        logger.info(f"Added order {e.jobId}: {order}")

    def post_sequence(self) -> None:
        super().post_sequence()

        index = self.executors[self.acc].index(self.scheduled_transfers)
        prev_validator = self.executors[self.acc][index - 1] if index > 0 else Account(1)

        op, _ = self.user_op(
            self.acc,
            self.simple_validator,
            abi.encode_call(self.acc.uninstallModule, [2, self.scheduled_transfers, abi.encode(prev_validator, b"")]),
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_add_order()

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_toggle_order()

        with must_revert((AssertionError, TransactionRevertedError)):
            self.flow_execute_order()

    def new_random_order(self) -> Order:
        return Order(
            execute_interval=random_int(1, 10),
            max_executions_count=random_int(1, 10),
            start=chain.blocks["pending"].timestamp + random_int(1, 10),
            recipient=random_account(),
            token=random.choice(TOKENS + [IERC20(Address.ZERO)]),
            amount=uint(random_int(0, 1000)),
        )

    @flow()
    def flow_add_order(self):
        order = self.new_random_order()

        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.scheduled_transfers,
            abi.encode_call(self.scheduled_transfers.addOrder, [order.payload]),
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        e = next(e for e in tx.events if isinstance(e, ScheduledTransfers.ExecutionAdded))
        self.orders[e.jobId] = order

        logger.info(f"Added order {e.jobId}: {order}")

    @flow()
    def flow_toggle_order(self):
        if len(self.orders) == 0:
            return

        order_id = random.choice(list(self.orders.keys()))

        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.scheduled_transfers,
            abi.encode_call(self.scheduled_transfers.toggleOrder, [order_id]),
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        self.orders[order_id].enabled = not self.orders[order_id].enabled

        logger.info(f"Toggled order {order_id}")

    @flow(weight=300)
    def flow_execute_order(self):
        if len(self.orders) == 0:
            return

        job_id, order = random.choice(list(self.orders.items()))

        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.scheduled_transfers,
            abi.encode_call(self.scheduled_transfers.executeOrder, [job_id]),
        )

        if order.token == Account(0):
            acc_before = self.acc.balance
            recipient_before = order.recipient.balance

            self.acc.balance += order.amount
        else:
            acc_before = order.token.balanceOf(self.acc)
            recipient_before = order.token.balanceOf(order.recipient)

            mint_erc20(order.token, self.acc, order.amount)

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        if not order.enabled:
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
        elif order.start > tx.block.timestamp:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledTransfers.InvalidExecution())
        else:
            assert e.success

            if order.token == Account(0):
                assert self.acc.balance == acc_before
                assert order.recipient.balance == recipient_before + order.amount
            else:
                assert order.token.balanceOf(self.acc) == acc_before
                assert order.token.balanceOf(order.recipient) == recipient_before + order.amount

            order.last_execution = tx.block.timestamp
            order.executions_count += 1

            logger.info(f"Executed order {job_id}: {order}")


@chain.connect(fork="http://localhost:8545")
def test_scheduled_transfers_fuzz():
    ScheduledTransfersTest().run(10, 1000)
