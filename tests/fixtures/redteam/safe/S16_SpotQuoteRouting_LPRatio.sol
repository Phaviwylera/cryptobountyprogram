pragma solidity ^0.8.0;
// Spot AMM reads that value nothing:
//  - a private reserves helper whose caller pairs liquidity after a minOut-protected swap (AgentMinter)
//  - getAmountsOut quotes that only pick a route, with swaps floored by minReceive (Stabilize strategy)
interface IPair { function getReserves() external view returns (uint112, uint112, uint32); function mint(address) external returns (uint256); }
interface IRouter {
    function getAmountsOut(uint256, address[] calldata) external view returns (uint256[] memory);
    function swapExactTokensForTokens(uint256, uint256, address[] calldata, address, uint256) external returns (uint256[] memory);
}
interface IERC20 { function transfer(address, uint256) external returns (bool); function balanceOf(address) external view returns (uint256); }

contract LiquidityMinter {
    IPair public immutable pair;
    IRouter public immutable router;
    IERC20 public immutable token;
    mapping(address => uint256) public lpOf;

    constructor(IPair p, IRouter r, IERC20 t) { pair = p; router = r; token = t; }

    function _reserves() private view returns (uint256 rToken, uint256 rWeth) {
        (uint112 r0, uint112 r1,) = pair.getReserves();
        (rToken, rWeth) = (uint256(r0), uint256(r1));
    }

    function _addLiquidity(uint256 bought, uint256 minOut, uint256 eth) private returns (uint256 lp) {
        require(bought >= minOut, "slippage");
        (uint256 rToken, uint256 rWeth) = _reserves();
        uint256 need = eth * rToken / rWeth;
        uint256 use = bought < need ? bought : need;
        token.transfer(address(pair), use);
        lp = pair.mint(address(this));
    }

    function stake(uint256 bought, uint256 minOut) external payable {
        lpOf[msg.sender] += _addLiquidity(bought, minOut, msg.value);
    }

    function _cheapest(address[] memory a, address[] memory b) internal view returns (bool) {
        uint256[] memory x = router.getAmountsOut(1e18, a);
        uint256[] memory y = router.getAmountsOut(1e18, b);
        return x[x.length - 1] > y[y.length - 1];
    }

    function rebalance(address[] calldata a, address[] calldata b, uint256 amt) external {
        address[] memory path = _cheapest(a, b) ? a : b;
        uint256 minReceiveBalance = amt;   // 1:1 peg floor
        router.swapExactTokensForTokens(amt, minReceiveBalance, path, address(this), block.timestamp);
    }
}
