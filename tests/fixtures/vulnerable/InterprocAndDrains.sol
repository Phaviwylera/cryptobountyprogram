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

// rescue that pays a CALLER-CHOSEN address - anyone drains it.
contract CallerRescue {
    function rescueToken(address tok, address to) external {
        IERC20(tok).transferFrom(address(this), to, 1);
    }
    function rescueNative(address payable to) external {
        _send(to);
    }
    function _send(address payable to) internal {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok);
    }
}

// PaymentHub-style: recover() moves any token anywhere, for anyone. (real finding from the backfill)
contract OpenRecover {
    function recover(address ercAddress, address to, uint256 amount) public {
        IERC20(ercAddress).transferFrom(address(this), to, amount);
    }
}

// An unprotected price setter that ALSO reads a feed is still a theft vector: the caller supplies the price.
interface IFeedLike { function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80); }
contract OpenPriceSetter {
    IFeedLike public feed; mapping(address => uint256) public price;
    function setPrice(address asset, uint256 newPrice) external {
        (, int256 ref, , , ) = feed.latestRoundData();
        require(ref > 0);
        price[asset] = newPrice;
    }
}

// Real backfill findings that must stay caught:
// CellarStaking-style: anyone can swap the staking token.
contract OpenStakingToken { address public stakingToken;
    function setStakingToken(address t) external { stakingToken = t; } }
// BitStake-style: pulls fee tokens from ANY approving user.
contract FeePuller { IERC20 public feeToken; address public collector;
    function depositNFT(address from, uint256 id, uint256 amountF) public { id; feeToken.transferFrom(from, collector, amountF); } }
