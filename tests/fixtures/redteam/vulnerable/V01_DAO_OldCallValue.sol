pragma solidity ^0.4.24;
// The DAO / SpankChain style: pre-0.6 `.call.value()` syntax
contract DAOVault {
    mapping(address => uint256) public balances;
    function deposit() public payable { balances[msg.sender] += msg.value; }
    function withdrawBalance() public {
        uint256 amount = balances[msg.sender];
        require(msg.sender.call.value(amount)());
        balances[msg.sender] = 0;
    }
}
