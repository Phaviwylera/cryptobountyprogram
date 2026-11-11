// Custodial withdrawal (BitGo-style MultiSigPoolV2): the recipient `to` is bound into a chainid-bound
// hash verified against the contract's OWN registered signer set (>= 2 of `signers`, `isAllowedSigner`),
// and `_recordOrder` marks the order id executed so a replay reverts.
// Must NOT flag "caller-chosen withdrawal" or "signature replay".
pragma solidity ^0.8.20;

interface IERC20 { function transfer(address to, uint256 amount) external returns (bool); }

library ECDSA {
    function recover(bytes32, bytes memory) internal pure returns (address) { return address(0); }
}

contract Custody {
    address[] public signers;
    bool public withdrawEnabled = true;

    struct Order { bool executed; address to; uint256 amount; }
    mapping(uint256 => Order) public orders;

    function isAllowedSigner(address signer) public view returns (bool) {
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == signer) return true;
        }
        return false;
    }

    function _verifySignatures(bytes32 digest, address[] memory allSigners, bytes[] memory sigs) internal view {
        require(allSigners.length >= 2 && allSigners.length <= signers.length, "invalid allSigners length");
        require(allSigners.length == sigs.length, "invalid signatures length");
        address previousSigner = address(0);
        for (uint256 i = 0; i < allSigners.length; i++) {
            address signer = allSigners[i];
            require(signer > previousSigner, "duplicate or unordered signer");
            require(isAllowedSigner(signer), "not allowed signer");
            require(ECDSA.recover(digest, sigs[i]) == signer, "invalid signer");
            previousSigner = signer;
        }
    }

    function _recordOrder(uint256 orderId, address to, uint256 amount) internal {
        if (orders[orderId].executed) revert("repeated order");
        orders[orderId].executed = true;
        orders[orderId].to = to;
        orders[orderId].amount = amount;
    }

    function withdrawErc20(
        address to,
        uint256 amount,
        address token,
        uint256 expireTime,
        uint256 orderId,
        address[] memory allSigners,
        bytes[] memory signatures
    ) public {
        require(withdrawEnabled, "withdraw disabled");
        require(to != address(0) && amount > 0, "invalid withdrawal");
        require(expireTime >= block.timestamp, "expired transaction");

        bytes32 operationHash = keccak256(
            abi.encodePacked("ERC20", to, amount, token, expireTime, orderId, address(this), block.chainid)
        );
        _verifySignatures(operationHash, allSigners, signatures);
        _recordOrder(orderId, to, amount);
        IERC20(token).transfer(to, amount);
    }
}
