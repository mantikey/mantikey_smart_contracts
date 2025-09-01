// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

contract MantiKey is EIP712 {
    using ECDSA for bytes32;

    // ------------------------------------------------
    // Storage
    // ------------------------------------------------
    mapping(address => bool) public isSigner;
    uint256 public signerCount;
    uint256 public threshold;

    uint256 public nonce; // shared for tx + pause/unpause
    bool public paused;

    enum ProposalType {
        AddSigner,
        RemoveSigner,
        ChangeThreshold,
        Pause,
        Unpause
    }

    struct Proposal {
        ProposalType pType;
        address target;
        uint256 newThreshold;
        uint256 votes;
        bool executed;
        mapping(address => bool) voted;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;

    // ------------------------------------------------
    // Constants
    // ------------------------------------------------
    bytes32 public constant TX_TYPEHASH =
        keccak256("Transaction(address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)");

    bytes32 public constant PAUSE_TYPEHASH =
        keccak256("Pause(bool pause,uint256 nonce,uint256 deadline)");

    // ------------------------------------------------
    // Events
    // ------------------------------------------------
    event ProposalCreated(uint256 indexed id, ProposalType pType, address target, uint256 newThr);
    event ProposalExecuted(uint256 indexed id);
    event Paused(address account);
    event Unpaused(address account);

    // ------------------------------------------------
    // Constructor
    // ------------------------------------------------
    constructor(address[3] memory signers, uint256 initialThreshold)
        EIP712("MantiKey", "1")
    {
        require(initialThreshold > 0, "thr 0");
        for (uint256 i = 0; i < signers.length; i++) {
            require(signers[i] != address(0), "zero");
            require(!isSigner[signers[i]], "dup");
            isSigner[signers[i]] = true;
            signerCount++;
        }
        threshold = initialThreshold;
    }

    // ------------------------------------------------
    // EIP712 Hashing Helpers
    // ------------------------------------------------
    function getTypedDataHash(
        address to,
        uint256 value,
        bytes memory data,
        uint256 txNonce,
        uint256 deadline
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                txNonce,
                deadline
            )
        );
        return _hashTypedDataV4(structHash);
    }

    function getPauseHash(
        bool _pause,
        uint256 pauseNonce,
        uint256 pauseDeadline
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                PAUSE_TYPEHASH,
                _pause,
                pauseNonce,
                pauseDeadline
            )
        );
        return _hashTypedDataV4(structHash);
    }

    // ------------------------------------------------
    // Transaction execution
    // ------------------------------------------------
    function execute(
        address to,
        uint256 value,
        bytes memory data,
        uint256 txNonce,
        uint256 deadline,
        bytes[] memory sigs
    ) external {
        require(!paused, "Contract is paused");
        require(txNonce == nonce, "bad nonce");
        require(block.timestamp <= deadline, "expired");

        bytes32 digest = getTypedDataHash(to, value, data, txNonce, deadline);
        _checkSignatures(digest, sigs);

        nonce++;
        (bool ok,) = to.call{value: value}(data);
        require(ok, "tx fail");
    }

    function canExecuteTransaction(
        address to,
        uint256 value,
        bytes memory data,
        uint256 txNonce,
        uint256 deadline,
        bytes[] memory sigs
    ) external view returns (bool, string memory) {
        if (paused) return (false, "Contract is paused");
        if (txNonce != nonce) return (false, "Invalid nonce");
        if (block.timestamp > deadline) return (false, "Deadline expired");

        bytes32 digest = getTypedDataHash(to, value, data, txNonce, deadline);
        try this.checkSignaturesView(digest, sigs) {
            return (true, "");
        } catch Error(string memory reason) {
            return (false, reason);
        }
    }

    // ------------------------------------------------
    // Pause / Unpause via signatures
    // ------------------------------------------------
    function pause(bytes[] memory sigs) external {
        require(!paused, "Already paused");
        uint256 pNonce = nonce;
        bytes32 digest = getPauseHash(true, pNonce, block.timestamp + 1 hours);
        _checkSignatures(digest, sigs);

        nonce++;
        paused = true;
        emit Paused(msg.sender);
    }

    function unpause(bytes[] memory sigs) external {
        require(paused, "Already unpaused");
        uint256 pNonce = nonce;
        bytes32 digest = getPauseHash(false, pNonce, block.timestamp + 1 hours);
        _checkSignatures(digest, sigs);

        nonce++;
        paused = false;
        emit Unpaused(msg.sender);
    }

    // ------------------------------------------------
    // Governance proposals (pause/unpause + others)
    // ------------------------------------------------
    function proposePause() external onlySigner {
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.Pause;
        emit ProposalCreated(pid, ProposalType.Pause, address(0), 0);
    }

    function proposeUnpause() external onlySigner {
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.Unpause;
        emit ProposalCreated(pid, ProposalType.Unpause, address(0), 0);
    }

    function proposeAddSigner(address newSigner) external onlySigner {
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.AddSigner;
        p.target = newSigner;
        emit ProposalCreated(pid, ProposalType.AddSigner, newSigner, 0);
    }

    function proposeRemoveSigner(address signer) external onlySigner {
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.RemoveSigner;
        p.target = signer;
        emit ProposalCreated(pid, ProposalType.RemoveSigner, signer, 0);
    }

    function proposeChangeThreshold(uint256 newThr) external onlySigner {
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.ChangeThreshold;
        p.newThreshold = newThr;
        emit ProposalCreated(pid, ProposalType.ChangeThreshold, address(0), newThr);
    }

    function vote(uint256 proposalId) external onlySigner {
        Proposal storage p = proposals[proposalId];
        require(!p.voted[msg.sender], "already");
        p.voted[msg.sender] = true;
        p.votes++;
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(!p.executed, "done");
        require(p.votes >= threshold, "not enough");

        p.executed = true;

        if (p.pType == ProposalType.AddSigner) {
            isSigner[p.target] = true;
            signerCount++;
        } else if (p.pType == ProposalType.RemoveSigner) {
            isSigner[p.target] = false;
            signerCount--;
        } else if (p.pType == ProposalType.ChangeThreshold) {
            threshold = p.newThreshold;
        } else if (p.pType == ProposalType.Pause) {
            require(!paused, "Already paused");
            paused = true;
            emit Paused(msg.sender);
        } else if (p.pType == ProposalType.Unpause) {
            require(paused, "Already unpaused");
            paused = false;
            emit Unpaused(msg.sender);
        }

        emit ProposalExecuted(proposalId);
    }

    // ------------------------------------------------
    // Internal signature check (order-agnostic)
    // ------------------------------------------------
    function _checkSignatures(bytes32 digest, bytes[] memory sigs) internal view {
        require(sigs.length >= threshold, "Not enough signatures");

        
        address[] memory seen = new address[](sigs.length);
        uint256 seenCount = 0;

        for (uint256 i = 0; i < sigs.length; i++) {
            address recovered = digest.recover(sigs[i]);
            require(isSigner[recovered], "not signer");

            // check duplicates manually
            for (uint256 j = 0; j < seenCount; j++) {
                require(seen[j] != recovered, "duplicate");
            }
            seen[seenCount++] = recovered;
        }
    }

    function checkSignaturesView(bytes32 digest, bytes[] memory sigs) external view {
        _checkSignatures(digest, sigs);
    }

    // ------------------------------------------------
    // Modifiers
    // ------------------------------------------------
    modifier onlySigner() {
        require(isSigner[msg.sender], "not signer");
        _;
    }

    // receive ether
    receive() external payable {}
}
