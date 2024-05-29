import logging
from dataclasses import dataclass
from wake.testing import *

from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.interfaces.IEntryPoint import IEntryPoint
from pytypes.source.examples.src.ScheduledOrders.ScheduledOrders import ScheduledOrders
from pytypes.source.examples.node_modules.forgestd.src.interfaces.IERC20 import IERC20

from .utils import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


TOKENS = [
    IERC20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), # usdc
    IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7"), # usdt
]


@dataclass
class Order:
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


class ScheduledOrdersTest(ExamplesTest):
    beneficiary: Account
    scheduled_orders: ScheduledOrders
    acc: MSAAdvanced

    orders: Dict[uint, Order]

    def pre_sequence(self) -> None:
        super().pre_sequence()

        self.orders = {}
        self.beneficiary = Account(1)
        self.scheduled_orders = ScheduledOrders.deploy()
        self.acc = self.new_smart_account()

        order = self.new_random_order()

        op, _ = self.user_op(
            self.acc,
            self.simple_validator,
            abi.encode_call(self.acc.installModule, [2, self.scheduled_orders, order.payload]),
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        self.executors[self.acc].insert(0, self.scheduled_orders)

        e = next(e for e in tx.events if isinstance(e, ScheduledOrders.ExecutionAdded))
        self.orders[e.jobId] = order

        logger.info(f"Added order {e.jobId}: {order}")

    def post_sequence(self) -> None:
        super().post_sequence()

        index = self.executors[self.acc].index(self.scheduled_orders)
        prev_validator = self.executors[self.acc][index - 1] if index > 0 else Account(1)

        op, _ = self.user_op(
            self.acc,
            self.simple_validator,
            abi.encode_call(self.acc.uninstallModule, [2, self.scheduled_orders, abi.encode(prev_validator, b"")]),
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
        if random_bool():
            token_in = IERC20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")  # usdc
            token_out = IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7")  # usdt
        else:
            token_in = IERC20("0xdac17f958d2ee523a2206206994597c13d831ec7")  # usdt
            token_out = IERC20("0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")  # usdc

        return Order(
            execute_interval=random_int(0, 10),
            max_executions_count=random_int(1, 10),
            start=chain.blocks["pending"].timestamp + random_int(1, 10),
            token_in=token_in,
            token_out=token_out,
            amount_in=uint(random_int(1, 10) * 10**token_in.decimals()),
            sqrt_price_limit_x96=uint160(0),
        )

    @flow()
    def flow_add_order(self):
        order = self.new_random_order()

        op, _ = self.erc7579_execute_op(
            self.acc,
            self.simple_validator,
            self.scheduled_orders,
            abi.encode_call(self.scheduled_orders.addOrder, [order.payload]),
        )

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        e = next(e for e in tx.events if isinstance(e, ScheduledOrders.ExecutionAdded))
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
            self.scheduled_orders,
            abi.encode_call(self.scheduled_orders.toggleOrder, [order_id]),
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
            self.scheduled_orders,
            abi.encode_call(self.scheduled_orders.executeOrder, [job_id]),
        )

        mint_erc20(order.token_in, self.acc, order.amount_in)

        in_before = order.token_in.balanceOf(self.acc)
        out_before = order.token_out.balanceOf(self.acc)

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        if not order.enabled:
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
        elif order.start > tx.block.timestamp:
            assert not e.success
            reason = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationRevertReason))
            assert reason.revertReason == abi.encode(ScheduledOrders.InvalidExecution())
        else:
            assert e.success

            assert order.token_in.balanceOf(self.acc) <= in_before
            assert order.token_out.balanceOf(self.acc) >= out_before

            order.last_execution = tx.block.timestamp
            order.executions_count += 1

            logger.info(f"Executed order {job_id}: {order}")


@chain.connect(fork="http://localhost:8545")
def test_scheduled_orders_fuzz():
    ScheduledOrdersTest().run(10, 1000)
