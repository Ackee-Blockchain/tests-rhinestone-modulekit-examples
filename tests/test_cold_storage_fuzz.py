from functools import partial
import logging
from wake.testing import *
from wake.testing.fuzzing import *

from pytypes.source.examples.node_modules.ERC4337.accountabstraction.contracts.interfaces.IEntryPoint import IEntryPoint
from pytypes.source.examples.src.OwnableExecutor.OwnableExecutor import OwnableExecutor
from pytypes.source.examples.src.OwnableValidator.OwnableValidator import OwnableValidator
from pytypes.source.examples.node_modules.forgestd.src.interfaces.IERC20 import IERC20
from pytypes.source.examples.src.ColdStorageHook.ColdStorageFlashloan import ColdStorageFlashloan
from pytypes.source.examples.src.ColdStorageHook.ColdStorageHook import ColdStorageHook
from pytypes.source.examples.node_modules.erc7579.src.interfaces.IERC7579Account import Execution
from pytypes.modulekit.src.mocks.MockValidator import MockValidator

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


class ColdStorageTest(ExamplesTest):
    beneficiary: Account
    ownable_executor: OwnableExecutor
    ownable_validator: OwnableValidator
    cold_storage_hook: ColdStorageHook
    cold_storage_flashloan: ColdStorageFlashloan
    mock_validator: MockValidator

    cold_wallet: MSAAdvanced
    main_wallet: MSAAdvanced

    cold_storage_executor_owner: Account
    owners: Dict[MSAAdvanced, List[Account]]
    owners_threshold: Dict[MSAAdvanced, int]
    hook_wait_period: uint128
    hook_owner: Account
    flashloan_nonce: uint

    def pre_sequence(self) -> None:
        super().pre_sequence()

        self.owners = {}
        self.owners_threshold = {}
        self.flashloan_nonce = uint(0)

        self.beneficiary = Account(1)
        self.ownable_executor = OwnableExecutor.deploy()
        self.ownable_validator = OwnableValidator.deploy()
        self.cold_storage_hook = ColdStorageHook.deploy()
        self.cold_storage_flashloan = ColdStorageFlashloan.deploy()
        self.mock_validator = MockValidator.deploy()

        owners = sorted(random.sample(chain.accounts, k=random_int(1, 10)), reverse=True)
        threshold = uint(random_int(1, len(owners)))

        self.cold_wallet = self.new_smart_account(
            self.ownable_validator,
            abi.encode(threshold, list(reversed(owners))),
        )
        self.owners[self.cold_wallet] = owners
        self.owners_threshold[self.cold_wallet] = threshold

        owners = sorted(random.sample(chain.accounts, k=random_int(1, 10)), reverse=True)
        threshold = uint(random_int(1, len(owners)))

        self.main_wallet = self.new_smart_account(
            self.ownable_validator,
            abi.encode(threshold, list(reversed(owners))),
        )
        self.owners[self.main_wallet] = owners
        self.owners_threshold[self.main_wallet] = threshold

        # install OwnableExecutor on cold wallet
        self.cold_storage_executor_owner = random_account()
        tx, e = self.execute(
            self.cold_wallet,
            self.cold_wallet,
            abi.encode_call(self.cold_wallet.installModule, [2, self.ownable_executor, bytes(self.cold_storage_executor_owner.address)]),
        )
        assert e.success

        # install ColdStorageHook on cold wallet
        self.hook_wait_period = uint128(random_int(1, 10))
        self.hook_owner = random.choice(chain.accounts)

        tx, e = self.execute(
            self.cold_wallet,
            self.cold_wallet,
            abi.encode_call(self.cold_wallet.installModule, [2, self.cold_storage_hook, abi.encode_packed(self.hook_wait_period, self.main_wallet)]),
        )
        assert e.success

        tx, e = self.execute(
            self.cold_wallet,
            self.cold_wallet,
            abi.encode_call(self.cold_wallet.installModule, [3, self.cold_storage_hook, ColdStorageHook.flashLoan.selector + b"\x00"]),
        )
        assert e.success

        tx, e = self.execute(
            self.cold_wallet,
            self.cold_wallet,
            abi.encode_call(self.cold_wallet.installModule, [4, self.cold_storage_hook, b""]),
        )
        assert e.success

        # install ColdStorageFlashloan on warm wallet
        tx, e = self.execute(
            self.main_wallet,
            self.main_wallet,
            abi.encode_call(self.main_wallet.installModule, [2, self.cold_storage_flashloan, abi.encode([self.cold_wallet])]),
        )
        assert e.success

        tx, e = self.execute(
            self.main_wallet,
            self.main_wallet,
            abi.encode_call(self.main_wallet.installModule, [3, self.cold_storage_flashloan, ColdStorageFlashloan.onFlashLoan.selector + b"\x00"]),
        )
        assert e.success

    @staticmethod
    def generate_signature(hash: bytes, owners: List[Account]) -> bytes:
        return b"".join(owner.sign(hash) for owner in owners)

    def execute(self, acc: MSAAdvanced, target: Account, calldata: bytes, value: int = 0) -> Tuple[TransactionAbc, IEntryPoint.UserOperationEvent]:
        # use OwnableValidator
        op, hash = self.erc7579_execute_op(
            acc,
            self.ownable_validator,
            target,
            calldata,
            value,
        )

        op.signature = bytearray(self.generate_signature(hash, random.sample(self.owners[acc], k=min(self.owners_threshold[acc], len(self.owners[acc])))))

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        return tx, e

    def install(self, acc: MSAAdvanced, module: Account, module_type: uint, init_data: bytes) -> Tuple[TransactionAbc, IEntryPoint.UserOperationEvent]:
        op, hash = self.user_op(
            acc,
            self.ownable_validator,
            data=abi.encode_call(MSAAdvanced.installModule, [module_type, module, init_data]),
        )

        op.signature = bytearray(self.generate_signature(hash, random.sample(self.owners[acc], k=min(self.owners_threshold[acc], len(self.owners[acc])))))

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        return tx, e

    def uninstall(self, acc: MSAAdvanced, module: Account, module_type: uint, deinit_data: bytes) -> Tuple[TransactionAbc, IEntryPoint.UserOperationEvent]:
        op, hash = self.user_op(
            acc,
            self.ownable_validator,
            data=abi.encode_call(MSAAdvanced.uninstallModule, [module_type, module, deinit_data]),
        )

        op.signature = bytearray(self.generate_signature(hash, random.sample(self.owners[acc], k=min(self.owners_threshold[acc], len(self.owners[acc])))))

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))

        return tx, e

    @flow()
    def flow_flashloan(self):
        acc = self.cold_wallet
        token = random.choice(TOKENS)
        amount = uint(random_int(1, 10) * 10**token.decimals())

        flash_loan_type = uint8(0)
        executions = [Execution(token.address, 0, bytearray(abi.encode_call(IERC20.transfer, [self.cold_wallet, amount])))]
        token_tx_hash = keccak256(abi.encode(flash_loan_type, executions, self.flashloan_nonce))
        hh = keccak256(b"\x19Ethereum Signed Message:\n" + f"{len(token_tx_hash)}".encode() + token_tx_hash)
        signature = bytes(self.ownable_validator.address) + self.generate_signature(hh, random.sample(self.owners[self.main_wallet], k=min(self.owners_threshold[self.main_wallet], len(self.owners[self.main_wallet]))))

        op, hash = self.user_op(
            acc,
            self.ownable_validator,
            data=abi.encode_call(ColdStorageHook.flashLoan, [self.main_wallet, token, amount, abi.encode(flash_loan_type, signature, executions)]),
        )
        op.signature = bytearray(self.generate_signature(hash, random.sample(self.owners[acc], k=min(self.owners_threshold[acc], len(self.owners[acc])))))

        mint_erc20(token, self.cold_wallet, amount)

        tx = ENTRY_POINY.handleOps([op], self.beneficiary)
        e = next(e for e in tx.events if isinstance(e, IEntryPoint.UserOperationEvent))
        assert e.success

        self.flashloan_nonce = uint(self.flashloan_nonce + 1)

    @flow()
    def flow_set_wait_period(self):
        acc = self.cold_wallet
        wait_period = uint128(random_int(1, 10))

        # enable setWaitPeriod execution
        execution = Execution(
            self.cold_storage_hook.address,
            0,
            bytearray(abi.encode_call(self.cold_storage_hook.setWaitPeriod, [wait_period])),
        )
        tx = self.ownable_executor.executeOnOwnedAccount(
            acc,
            abi.encode_packed(self.cold_storage_hook, uint(0), abi.encode_call(self.cold_storage_hook.requestTimelockedExecution, [execution, 0])),
            from_=self.cold_storage_executor_owner,
        )

        exec = partial(self.ownable_executor.executeOnOwnedAccount,
            acc,
            abi.encode_packed(self.cold_storage_hook, uint(0), abi.encode_call(self.cold_storage_hook.setWaitPeriod, [wait_period])),
            from_=self.cold_storage_executor_owner,
        )

        if self.hook_wait_period != 1:
            chain.set_next_block_timestamp(tx.block.timestamp + self.hook_wait_period - 1)

            with must_revert() as e:
                exec()

            chain.mine()

        exec()

        self.hook_wait_period = wait_period

    @flow()
    def flow_install_uninstall_module(self):
        acc = self.cold_wallet

        # install module
        tx = self.ownable_executor.executeOnOwnedAccount(
            acc,
            abi.encode_packed(self.cold_storage_hook, uint(0), abi.encode_call(self.cold_storage_hook.requestTimelockedModuleConfig, [1, self.mock_validator, b"", True, 0])),
            from_=self.cold_storage_executor_owner,
        )

        exec = partial(self.install,
            acc,
            self.mock_validator,
            1,
            b"",
        )

        if self.hook_wait_period != 1:
            chain.set_next_block_timestamp(tx.block.timestamp + self.hook_wait_period - 1)

            tx, e = exec()
            assert not e.success

            chain.mine()

        tx, e = exec()
        assert e.success

        # uninstall module
        tx = self.ownable_executor.executeOnOwnedAccount(
            acc,
            abi.encode_packed(self.cold_storage_hook, uint(0), abi.encode_call(self.cold_storage_hook.requestTimelockedModuleConfig, [1, self.mock_validator, abi.encode(Address(1), b""), False, 0])),
            from_=self.cold_storage_executor_owner,
        )

        exec = partial(self.uninstall,
            acc,
            self.mock_validator,
            1,
            abi.encode(Address(1), b""),
        )

        if self.hook_wait_period != 1:
            chain.set_next_block_timestamp(tx.block.timestamp + self.hook_wait_period - 1)

            tx, e = exec()
            assert not e.success

            chain.mine()

        tx, e = exec()
        assert e.success


@chain.connect(fork="http://localhost:8545")
def test_cold_storage_fuzz():
    ColdStorageTest().run(10, 10_000)
