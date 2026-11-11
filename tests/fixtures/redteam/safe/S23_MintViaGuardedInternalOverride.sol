// Public mint() delegates to an OVERRIDDEN internal _mint carrying onlyMinter (PowerfulERC20 /
// erc20-generator pattern). The access control is real, just not on the public wrapper's own modifier.
// Must NOT flag "anyone can mint tokens/shares without paying".
pragma solidity ^0.7.0;

abstract contract ERC20Min {
    mapping(address => uint256) internal _balances;
    uint256 public totalSupply;

    function _mint(address account, uint256 amount) internal virtual {
        _balances[account] += amount;
        totalSupply += amount;
    }

    // WARNING (from the base): access control MUST be defined in derived contracts.
    function mint(address account, uint256 amount) public {
        _mint(account, amount);
    }
}

contract GuardedToken is ERC20Min {
    mapping(address => bool) public isMinter;

    modifier onlyMinter() {
        require(isMinter[msg.sender], "caller does not have the MINTER role");
        _;
    }

    function _mint(address account, uint256 amount) internal override onlyMinter {
        super._mint(account, amount);
    }
}
