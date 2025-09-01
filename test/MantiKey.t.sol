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

    // =========================================================
    // 3) Test pause/unpause functionality
    // =========================================================
    function test_PauseUnpause_BlocksAndAllowsTransactions() public {
        // Test contract starts unpaused
        assertFalse(multiSig.paused(), "Contract should start unpaused");

        // Create pause signatures
        uint256 pauseNonce = multiSig.nonce();
        uint256 pauseDeadline = block.timestamp + 1 hours;
        bytes32 pauseHash = multiSig.getPauseHash(true, pauseNonce, pauseDeadline);

        bytes[] memory pauseSigs = new bytes[](2);
        pauseSigs[0] = _signDigest(pauseHash, SIGNER1_PRIVATE_KEY);
        pauseSigs[1] = _signDigest(pauseHash, SIGNER2_PRIVATE_KEY);

        // Pause the contract
        multiSig.pause(pauseSigs);

        assertTrue(multiSig.paused(), "Contract should be paused");

        // Try to execute transaction while paused - should fail
        // Need to use current nonce after pause operation
        uint256 currentNonce = multiSig.nonce();
        uint256 deadline = block.timestamp + 1 days;
        bytes32 digest = multiSig.getTypedDataHash(recipientA, 0.1 ether, "", currentNonce, deadline);
        
        bytes[] memory txSigs = new bytes[](2);
        txSigs[0] = _signDigest(digest, SIGNER1_PRIVATE_KEY);
        txSigs[1] = _signDigest(digest, SIGNER2_PRIVATE_KEY);

        vm.expectRevert("Contract is paused");
        multiSig.execute(recipientA, 0.1 ether, "", currentNonce, deadline, txSigs);

        // Verify canExecuteTransaction returns correct error
        (bool canExecute, string memory reason) = multiSig.canExecuteTransaction(
            recipientA, 0.1 ether, "", currentNonce, deadline, txSigs
        );
        assertFalse(canExecute, "Should not be able to execute while paused");
        assertEq(reason, "Contract is paused", "Should return pause reason");

        // Create unpause signatures
        uint256 unpauseNonce = multiSig.nonce();
        uint256 unpauseDeadline = block.timestamp + 1 hours;
        bytes32 unpauseHash = multiSig.getPauseHash(false, unpauseNonce, unpauseDeadline);

        bytes[] memory unpauseSigs = new bytes[](2);
        unpauseSigs[0] = _signDigest(unpauseHash, SIGNER1_PRIVATE_KEY);
        unpauseSigs[1] = _signDigest(unpauseHash, SIGNER2_PRIVATE_KEY);

        // Unpause the contract
        multiSig.unpause(unpauseSigs);

        assertFalse(multiSig.paused(), "Contract should be unpaused");

        // Now transaction should work
        uint256 balA0 = recipientA.balance;
        _executeTx(
            recipientA,
            0.1 ether,
            "",
            _arr2(SIGNER1_PRIVATE_KEY, SIGNER2_PRIVATE_KEY)
        );
        assertEq(recipientA.balance, balA0 + 0.1 ether, "recipientA should receive ETH");
    }

    function test_PauseUnpause_RequiresThresholdSignatures() public {
        // Try to pause with only 1 signature - should fail
        uint256 pauseNonce = multiSig.nonce();
        uint256 pauseDeadline = block.timestamp + 1 hours;
        bytes32 pauseHash = multiSig.getPauseHash(true, pauseNonce, pauseDeadline);

        bytes[] memory insufficientSigs = new bytes[](1);
        insufficientSigs[0] = _signDigest(pauseHash, SIGNER1_PRIVATE_KEY);

        vm.expectRevert("Not enough signatures");
        multiSig.pause(insufficientSigs);

        // Should still be unpaused
        assertFalse(multiSig.paused(), "Contract should remain unpaused");
    }

    function test_PauseUnpause_CannotDoubleAction() public {
        // Pause first
        uint256 pauseNonce = multiSig.nonce();
        uint256 pauseDeadline = block.timestamp + 1 hours;
        bytes32 pauseHash = multiSig.getPauseHash(true, pauseNonce, pauseDeadline);

        bytes[] memory pauseSigs = new bytes[](2);
        pauseSigs[0] = _signDigest(pauseHash, SIGNER1_PRIVATE_KEY);
        pauseSigs[1] = _signDigest(pauseHash, SIGNER2_PRIVATE_KEY);

        multiSig.pause(pauseSigs);
        assertTrue(multiSig.paused(), "Should be paused");

        // Try to pause again - should fail
        vm.expectRevert("Already paused");
        multiSig.pause(pauseSigs);

        // Unpause
        uint256 unpauseNonce = multiSig.nonce();
        uint256 unpauseDeadline = block.timestamp + 1 hours;
        bytes32 unpauseHash = multiSig.getPauseHash(false, unpauseNonce, unpauseDeadline);

        bytes[] memory unpauseSigs = new bytes[](2);
        unpauseSigs[0] = _signDigest(unpauseHash, SIGNER1_PRIVATE_KEY);
        unpauseSigs[1] = _signDigest(unpauseHash, SIGNER2_PRIVATE_KEY);

        multiSig.unpause(unpauseSigs);
        assertFalse(multiSig.paused(), "Should be unpaused");

        // Try to unpause again - should fail
        vm.expectRevert("Already unpaused");
        multiSig.unpause(unpauseSigs);
    }

    function test_PauseUnpause_ViaGovernanceProposals() public {
        // Test pause via governance proposal
        address[] memory voters2 = new address[](2);
        voters2[0] = signer1;
        voters2[1] = signer2;

        uint256 pauseProposalId = multiSig.proposalCount();
        vm.prank(signer1);
        multiSig.proposePause();

        // Vote on pause proposal
        vm.prank(signer1);
        multiSig.vote(pauseProposalId);
        vm.prank(signer2);
        multiSig.vote(pauseProposalId);

        // Execute pause proposal
        multiSig.executeProposal(pauseProposalId);
        assertTrue(multiSig.paused(), "Contract should be paused via governance");

        // Test unpause via governance proposal
        uint256 unpauseProposalId = multiSig.proposalCount();
        vm.prank(signer1);
        multiSig.proposeUnpause();

        // Vote on unpause proposal
        vm.prank(signer1);
        multiSig.vote(unpauseProposalId);
        vm.prank(signer2);
        multiSig.vote(unpauseProposalId);

        // Execute unpause proposal
        multiSig.executeProposal(unpauseProposalId);
        assertFalse(multiSig.paused(), "Contract should be unpaused via governance");
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