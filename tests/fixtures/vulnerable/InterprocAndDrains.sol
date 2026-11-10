// SPDX-License-Identifier: MIT
// INTENTIONALLY VULNERABLE - regression fixtures for interprocedural + drain detectors. Never deploy.
pragma solidity ^0.8.20;

interface IERC20 { function transferFrom(address,address,uint256) external returns (bool); function approve(address,uint256) external returns (bool); }

// reentrancy where the state write is in an internal helper (V03/V04 shape)
contract HelperWriteVault {
    mapping(address => uint256) public credit;
    function deposit() external payable { credit[msg.sender] += msg.value; }
    function withdraw() external {
        uint256 amt = credit[msg.sender];
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok);
        _clear(msg.sender);
    }
    function _clear(address who) internal { credit[who] = 0; }
}

// arbitrary transferFrom - drains approvals
contract ApprovalDrainer {
    function pull(address token, address from, address to, uint256 amount) external {
        IERC20(token).transferFrom(from, to, amount);
    }
}

// arbitrary approval to a caller-chosen spender
contract ApprovalGiver {
    IERC20 public token;
    function allow(address spender) external {
        token.approve(spender, type(uint256).max);
    }
}

// cross-function reentrancy: borrow (guarded) shares collateral with exitMarket (unguarded, pays out)
contract CrossFn {
    uint256 private _lock = 1;
    modifier guard() { require(_lock == 1); _lock = 2; _; _lock = 1; }
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    function supply() external payable { collateral[msg.sender] += msg.value; }
    function borrow(uint256 amount) external guard {
        require(collateral[msg.sender] >= debt[msg.sender] + amount * 2);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        debt[msg.sender] += amount;
    }
    function exitMarket() external {
        require(debt[msg.sender] == 0, "has debt");
        uint256 c = collateral[msg.sender];
        collateral[msg.sender] = 0;
        payable(msg.sender).transfer(c);
    }
}
