// MEV arb-bot pattern: swap-callback forwards to an internal helper that pins msg.sender to
// the expected Uniswap-V3 pool by packed-address compare. Must NOT flag as "callback without auth".
pragma solidity ^0.8.20;

contract Bot {
    address immutable OWNER;

    constructor() { OWNER = msg.sender; }

    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        _v3Callback(amount0Delta, amount1Delta, data);
    }

    function pancakeV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        _v3Callback(amount0Delta, amount1Delta, data);
    }

    function _v3Callback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) internal {
        // packed-address auth: the low 12 bytes of msg.sender must equal the expected pool's
        // low 12 bytes carried inside the callback's `data`.
        address expected;
        assembly { expected := shr(96, calldataload(data.offset)) }
        require(uint96(uint160(msg.sender)) == uint96(uint160(expected)), "wtf");
        address token;
        assembly { token := shr(96, calldataload(add(data.offset, 20))) }
        if (amount0Delta > 0) IERC20(token).transfer(msg.sender, uint256(amount0Delta));
        if (amount1Delta > 0) IERC20(token).transfer(msg.sender, uint256(amount1Delta));
    }
}

interface IERC20 { function transfer(address, uint256) external returns (bool); }
