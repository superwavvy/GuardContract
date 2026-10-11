// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract VulnerableRouter {
    address public coreRegistry;
    address public owner;

    constructor(address _registry) {
        coreRegistry = _registry;
        owner = msg.sender;
    }

    // VULNERABLE: no access control, forwards caller-supplied calldata
    function forwardRequest(
        string memory _serviceName,
        string memory _serviceId,
        bytes calldata _funcEncodeWithSignature
    ) external {
        address service = _getServiceInstance(_serviceName, _serviceId);
        require(service != address(0), "Service not implemented");
        (bool success, ) = service.call(_funcEncodeWithSignature);
        require(success, "Forward failed");
    }

    // SAFE: properly gated
    function adminForward(
        address service,
        bytes calldata _funcEncodeWithSignature
    ) external onlyOwner {
        (bool success, ) = service.call(_funcEncodeWithSignature);
        require(success, "Forward failed");
    }

    function _getServiceInstance(string memory, string memory) internal view returns (address) {
        return coreRegistry;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
}
