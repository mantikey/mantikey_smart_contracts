// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "../src/MantiKey.sol";

contract MantiKeyTest_Extended is Test {
    MantiKey multiSig;

    // Foundry default test keys (don't use them anywere, they are just for testing)
    uint256 private constant SIGNER1_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    uint256 private constant SIGNER2_PRIVATE_KEY = 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d;
    uint256 private constant SIGNER3_PRIVATE_KEY = 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a;

    address signer1;
    address signer2;
    address signer3;

    // fresh 4th signer (addr + pk)
    address signer4;
    uint256 signer4Pk;
    

    address recipientA = makeAddr("recipientA");
    address recipientB = makeAddr("recipientB");

    uint256 initialThreshold = 2;

    function setUp() public {
        signer1 = vm.addr(SIGNER1_PRIVATE_KEY);
        signer2 = vm.addr(SIGNER2_PRIVATE_KEY);
        signer3 = vm.addr(SIGNER3_PRIVATE_KEY);

        address[3] memory signerArray = [signer1, signer2, signer3];
        multiSig = new MantiKey(signerArray, initialThreshold);

        // Fund wallet
        vm.deal(address(multiSig), 3 ether);

        // Create deterministic 4th signer (addr + pk)
        (signer4, signer4Pk) = makeAddrAndKey("signer4");
    }

    // Events for testing
    event Paused(address account);
    event Unpaused(address account);

    // -------------------------
    // helpers
    // -------------------------
    function _proposeVoteExecuteAdd(address newSigner, address[] memory voters) internal returns (uint256) {
        uint256 pid = multiSig.proposalCount();
        vm.prank(voters[0]);
        multiSig.proposeAddSigner(newSigner);

        for (uint256 i = 0; i < voters.length; i++) {
            vm.prank(voters[i]);
            multiSig.vote(pid);
        }
        multiSig.executeProposal(pid);
        return pid;
    }

    function _proposeVoteExecuteRemove(address signerToRemove, address[] memory voters) internal returns (uint256) {
        uint256 pid = multiSig.proposalCount();
        vm.prank(voters[0]);
        multiSig.proposeRemoveSigner(signerToRemove);

        for (uint256 i = 0; i < voters.length; i++) {
            vm.prank(voters[i]);
            multiSig.vote(pid);
        }
        multiSig.executeProposal(pid);
        return pid;
    }

    function _proposeVoteExecuteChangeThreshold(uint256 newThreshold, address[] memory voters) internal returns (uint256) {
        uint256 pid = multiSig.proposalCount();
        vm.prank(voters[0]);
        multiSig.proposeChangeThreshold(newThreshold);

        for (uint256 i = 0; i < voters.length; i++) {
            vm.prank(voters[i]);
            multiSig.vote(pid);
        }
        multiSig.executeProposal(pid);
        return pid;
    }

    function _signDigest(bytes32 digest, uint256 pk) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _executeTx(address to, uint256 value, bytes memory data, uint256[] memory pks) internal {
        uint256 txNonce = multiSig.nonce();
        uint256 deadline = block.timestamp + 1 days;
        bytes32 digest = multiSig.getTypedDataHash(to, value, data, txNonce, deadline);

        bytes[] memory sigs = new bytes[](pks.length);
        for (uint256 i = 0; i < pks.length; i++) {
            sigs[i] = _signDigest(digest, pks[i]);
        }
        multiSig.execute(to, value, data, txNonce, deadline, sigs);
    }

    // =========================================================
    // 1) Add another signer -> send tx (thr=2) -> set thr=3 -> send tx (thr=3)
    // =========================================================
    function test_AddSigner_SendTx_ThenChangeThresholdTo3_AndSendTx() public {
        // voters2: threshold 2
        address[] memory voters2 = new address[](2);
        voters2[0] = signer1;
        voters2[1] = signer2;

        _proposeVoteExecuteAdd(signer4, voters2);

        assertTrue(multiSig.isSigner(signer4), "signer4 should be a signer now");
        assertEq(multiSig.signerCount(), 4, "signer count should be 4");
        assertEq(multiSig.threshold(), 2, "threshold should remain 2");

        // Send 0.5 ETH with 2 sigs
        uint256 balA0 = recipientA.balance;
        _executeTx(
            recipientA,
            0.5 ether,
            "",
            _arr2(SIGNER1_PRIVATE_KEY, SIGNER2_PRIVATE_KEY)
        );
        assertEq(recipientA.balance, balA0 + 0.5 ether, "recipientA +0.5 ETH");

        // Change threshold to 3
        _proposeVoteExecuteChangeThreshold(3, voters2);
        assertEq(multiSig.threshold(), 3, "threshold should be 3 now");

        // Send 0.75 ETH with 3 sigs
        uint256 balB0 = recipientB.balance;
        _executeTx(
            recipientB,
            0.75 ether,
            "",
            _arr3(SIGNER1_PRIVATE_KEY, SIGNER2_PRIVATE_KEY, SIGNER3_PRIVATE_KEY)
        );
        assertEq(recipientB.balance, balB0 + 0.75 ether, "recipientB +0.75 ETH");
    }

    // =========================================================
    // 2) Remove a signer -> change threshold back to 2 -> send tx (thr=2)
    // =========================================================
    function test_RemoveSigner_AndChangeThresholdBackTo2_AndSendTx() public {
        // voters2: threshold 2 for adding signer
        address[] memory voters2 = new address[](2);
        voters2[0] = signer1;
        voters2[1] = signer2;

        _proposeVoteExecuteAdd(signer4, voters2);
        assertEq(multiSig.signerCount(), 4);

        // Raise threshold to 3
        _proposeVoteExecuteChangeThreshold(3, voters2);
        assertEq(multiSig.threshold(), 3);

        // voters3: need 3 votes for remove
        address[] memory voters3 = new address[](3);
        voters3[0] = signer1;
        voters3[1] = signer2;
        voters3[2] = signer3;

        _proposeVoteExecuteRemove(signer4, voters3);
        assertEq(multiSig.signerCount(), 3);
        assertFalse(multiSig.isSigner(signer4), "signer4 removed");

        // Lower threshold back to 2
        _proposeVoteExecuteChangeThreshold(2, voters3);
        assertEq(multiSig.threshold(), 2, "threshold back to 2");

        // Send 0.4 ETH with 2 signatures
        uint256 balA0 = recipientA.balance;
        _executeTx(
            recipientA,
            0.4 ether,
            "",
            _arr2(SIGNER1_PRIVATE_KEY, SIGNER2_PRIVATE_KEY)
        );
        assertEq(recipientA.balance, balA0 + 0.4 ether, "recipientA +0.4 ETH");
    }

     function testGetAllSigners() public {
        // Test initial signers
        address[] memory signers = multiSig.getAllSigners();
        
        assertEq(signers.length, 3);
        assertEq(signers[0], signer1);
        assertEq(signers[1], signer2);
        assertEq(signers[2], signer3);
        
        // Verify all returned addresses are actually signers
        for (uint256 i = 0; i < signers.length; i++) {
            assertTrue(multiSig.isSigner(signers[i]));
        }
    }


     function testGetAllSignersAfterAddingSigner() public {
        address newSigner = address(0x4);
        // Create and execute proposal to add a new signer
        vm.prank(signer1);
        multiSig.proposeAddSigner(newSigner);
        
        // Vote on the proposal
        vm.prank(signer1);
        multiSig.vote(0);
        vm.prank(signer2);
        multiSig.vote(0);
        
        // Execute the proposal
        multiSig.executeProposal(0);
        
        // Check updated signers list
        address[] memory signers = multiSig.getAllSigners();
        assertEq(signers.length, 4);
        
        // Verify the new signer is included
        bool newSignerFound = false;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == newSigner) {
                newSignerFound = true;
                break;
            }
        }
        assertTrue(newSignerFound);
        assertTrue(multiSig.isSigner(newSigner));
    }

    function testGetAllSignersAfterRemovingSigner() public {
        // Create and execute proposal to remove a signer
        vm.prank(signer1);
        multiSig.proposeRemoveSigner(signer3);
        
        // Vote on the proposal
        vm.prank(signer1);
        multiSig.vote(0);
        vm.prank(signer2);
        multiSig.vote(0);
        
        // Execute the proposal
        multiSig.executeProposal(0);
        
        // Check updated signers list
        address[] memory signers = multiSig.getAllSigners();
        assertEq(signers.length, 2);
        
        // Verify the removed signer is not included
        for (uint256 i = 0; i < signers.length; i++) {
            assertFalse(signers[i] == signer3);
        }
        
        // Verify signer3 is no longer a signer
        assertFalse(multiSig.isSigner(signer3));
        
        // Verify remaining signers are still there
        bool signer1Found = false;
        bool signer2Found = false;
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == signer1) signer1Found = true;
            if (signers[i] == signer2) signer2Found = true;
        }
        assertTrue(signer1Found || signer2Found); // At least one should be found
        assertTrue(multiSig.isSigner(signer1));
        assertTrue(multiSig.isSigner(signer2));
    }

    // utility arrays
    function _arr2(uint256 a, uint256 b) internal pure returns (uint256[] memory out) {
        out = new uint256[](2);
        out[0] = a;
        out[1] = b;
    }

    function _arr3(uint256 a, uint256 b, uint256 c) internal pure returns (uint256[] memory out) {
        out = new uint256[](3);
        out[0] = a;
        out[1] = b;
        out[2] = c;
    }
}