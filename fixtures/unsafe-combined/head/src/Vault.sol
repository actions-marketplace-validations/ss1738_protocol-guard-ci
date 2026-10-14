// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.28;

/// Minimal UUPS-style vault used as a Protocol Guard CI fixture.
contract Vault {
    bytes32 internal constant IMPL_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    bool public paused;
    address public owner;
    uint256 public totalDeposits;
    mapping(address => uint256) public balances;

    event Upgraded(address indexed implementation);

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function initialize(address initialOwner) external {
        require(owner == address(0), "initialized");
        owner = initialOwner;
    }

    function version() external pure returns (uint256) {
        return 1;
    }

    function deposit() external payable {
        require(!paused, "paused");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
    }

    function withdraw(uint256 amount) external {
        balances[msg.sender] -= amount;
        totalDeposits -= amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    function withdrawAll(address payable to) external onlyOwner {
        uint256 bal = address(this).balance;
        (bool ok,) = to.call{value: bal}("");
        require(ok, "transfer failed");
    }

    function execute(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "call failed");
        return ret;
    }

    function setPaused(bool p) external onlyOwner {
        paused = p;
    }

    function upgradeTo(address implementation) external {
        _authorizeUpgrade(implementation);
        bytes32 slot = IMPL_SLOT;
        assembly {
            sstore(slot, implementation)
        }
        emit Upgraded(implementation);
    }

    function _authorizeUpgrade(address) internal view {}
}
