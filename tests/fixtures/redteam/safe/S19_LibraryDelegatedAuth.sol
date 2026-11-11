// Library-delegated admin pattern: the top-level wrapper looks unguarded, but delegates
// to a library whose implementation enforces `msg.sender == s.modules.waterfall`.
// Must NOT flag as "privileged function callable by anyone".
pragma solidity ^0.8.20;

library ReserveAccrualLib {
    struct State { address waterfall; uint16 feeBps; address recipient; }

    function setFee(State storage s, uint16 feeBps_, address recipient_) public {
        require(msg.sender == s.waterfall, "NotWaterfall");
        require(feeBps_ <= 1000, "FeeTooHigh");
        require(recipient_ != address(0), "ZeroRecipient");
        s.feeBps = feeBps_;
        s.recipient = recipient_;
    }
}

contract ReserveManager {
    ReserveAccrualLib.State internal s;

    function setAccrualFee(uint16 feeBps, address recipient) external {
        ReserveAccrualLib.setFee(s, feeBps, recipient);
    }
}
