// A `public` library setter taking a `storage` reference ($) is internal plumbing: a storage pointer
// cannot cross the ABI boundary, so the library function is NOT externally callable. The real entrypoint
// is the guarded wrapper (`external onlySafe`). Lagoon/ERC7540 vault pattern (FeeLib, AccessableLib).
// Must NOT flag "privileged function callable by anyone".
pragma solidity ^0.8.20;

library FeeLib {
    struct FeeStore { uint256 highWaterMark; address safe; }

    function setHighWaterMark(FeeStore storage $, uint256 newHwm) public {
        $.highWaterMark = newHwm;
    }
}

contract Vault {
    using FeeLib for FeeLib.FeeStore;
    FeeLib.FeeStore internal $;
    address public safe;

    modifier onlySafe() {
        require(msg.sender == safe, "only safe");
        _;
    }

    function setHighWaterMark(uint256 newHwm) external onlySafe {
        FeeLib.setHighWaterMark($, newHwm);
    }
}
