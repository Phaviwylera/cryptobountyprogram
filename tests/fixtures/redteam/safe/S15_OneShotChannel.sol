pragma solidity ^0.8.0;
// One-shot payment channel (Web3Provider): the client's signature can only ever be redeemed once,
// because `charged` is checked and then set.
contract Channel {
    address public provider;
    address public client;
    uint256 public deposit;
    bool public charged;

    constructor() { provider = msg.sender; }

    function subscribe() external payable {
        require(client == address(0));
        client = msg.sender;
        deposit = msg.value;
    }

    function charge(uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        require(charged == false);
        require(msg.sender == provider);
        bytes32 hash = keccak256(abi.encodePacked(block.chainid, address(this), amount));
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0) && signer == client);
        require(amount <= deposit);
        charged = true;
        payable(provider).transfer(amount);
    }
}
