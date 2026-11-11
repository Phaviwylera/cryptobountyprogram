pragma solidity ^0.4.9;
// EtherDelta-style exchange (Pinexz): legacy `if (msg.sender != admin) throw;` guards, and order
// signatures that cannot be replayed because fills are tracked per signed hash.
contract SafeMath {
  function safeMul(uint a, uint b) internal returns (uint) { uint c = a * b; assert(a == 0 || c / a == b); return c; }
  function safeSub(uint a, uint b) internal returns (uint) { assert(b <= a); return a - b; }
  function safeAdd(uint a, uint b) internal returns (uint) { uint c = a + b; assert(c >= a && c >= b); return c; }
}

contract Exchange is SafeMath {
  address public admin;
  mapping (address => mapping (address => uint)) public tokens;
  mapping (address => mapping (bytes32 => uint)) public orderFills;

  function Exchange(address admin_) { admin = admin_; }

  function changeAdmin(address admin_) {
    if (msg.sender != admin) throw;
    admin = admin_;
  }

  function trade(address tokenGet, uint amountGet, address tokenGive, uint amountGive, uint expires, uint nonce,
                 address user, uint8 v, bytes32 r, bytes32 s, uint amount) {
    if (user == address(0)) throw;
    bytes32 hash = sha256(this, tokenGet, amountGet, tokenGive, amountGive, expires, nonce, block.chainid);
    if (!(ecrecover(sha3("\x19Ethereum Signed Message:\n32", hash), v, r, s) == user &&
          block.number <= expires && safeAdd(orderFills[user][hash], amount) <= amountGet)) throw;
    tokens[tokenGet][msg.sender] = safeSub(tokens[tokenGet][msg.sender], amount);
    tokens[tokenGet][user] = safeAdd(tokens[tokenGet][user], amount);
    tokens[tokenGive][user] = safeSub(tokens[tokenGive][user], safeMul(amountGive, amount) / amountGet);
    tokens[tokenGive][msg.sender] = safeAdd(tokens[tokenGive][msg.sender], safeMul(amountGive, amount) / amountGet);
    orderFills[user][hash] = safeAdd(orderFills[user][hash], amount);
  }
}
