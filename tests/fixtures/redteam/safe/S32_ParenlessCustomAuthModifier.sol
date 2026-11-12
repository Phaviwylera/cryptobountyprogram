// A custom access modifier declared WITHOUT parentheses (`modifier byDFO virtual { ... }` from the DFOhub
// framework; `modifier isSigner { ... }`) still gates the function to an authorized caller via its
// msg.sender body. The member parser used to require "(" after a modifier name, so these were invisible
// and every function they guard read as unprotected. Must NOT flag the setters as
// "privileged function callable by anyone".
pragma solidity ^0.8.0;

contract WUSDExtensionController {
    address private doubleProxy;
    address private signer;

    function _isFromDFO(address sender) internal view returns (bool) {
        return sender == doubleProxy;
    }

    modifier byDFO virtual {
        require(_isFromDFO(msg.sender), "Unauthorized action");
        _;
    }

    modifier isSigner {
        require(msg.sender == signer, "This function can only be called by a signer");
        _;
    }

    function setDoubleProxy(address newDoubleProxy) public byDFO {
        doubleProxy = newDoubleProxy;
    }

    function updateSigner(address newSigner) external isSigner {
        signer = newSigner;
    }
}
