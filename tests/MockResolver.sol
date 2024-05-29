import "@rhinestone/registry/src/Registry.sol";
import "@rhinestone/registry/src/external/IExternalResolver.sol";
import "@rhinestone/registry/src/external/examples/ResolverBase.sol";


contract MockResolver is ResolverBase {


    constructor(Registry _registry) ResolverBase(_registry) {

    }

    function resolveAttestation(AttestationRecord calldata attestation) external override payable returns (bool){
        return true;
    }

    function resolveAttestation(AttestationRecord[] calldata attestation) external override payable returns (bool){
        return true;
    }

    function resolveRevocation(AttestationRecord calldata attestation) external override payable returns (bool){
        return true;
    }
    function resolveRevocation(AttestationRecord[] calldata attestation) external override payable returns (bool){
        return true;
    }

    function resolveModuleRegistration(
        address sender,
        address moduleAddress,
        ModuleRecord calldata record
    )
        external
        payable
        returns (bool){
            return true;
        }

    function supportsInterface(bytes4 interfaceID) external override view returns (bool){
        return type(IExternalResolver).interfaceId == interfaceID;
    }

}