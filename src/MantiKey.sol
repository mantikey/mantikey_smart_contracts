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

    uint256 public nonce; // shared for tx
    
    enum ProposalType {
        AddSigner,
        RemoveSigner,
        ChangeThreshold        
    }

    struct Proposal {
        ProposalType pType;
        address target;
        uint256 newThreshold;
        uint256 votes;
        bool executed;
        uint256 createdAt;        
        uint256 deadline; // 7 days from creation
        mapping(address => bool) voted;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;

    // ------------------------------------------------
    // Constants
    // ------------------------------------------------
    bytes32 public constant TX_TYPEHASH =
        keccak256("Transaction(address to,uint256 value,bytes data,uint256 nonce,uint256 deadline)");

    uint256 public constant PROPOSAL_DURATION = 7 days;

    // ------------------------------------------------
    // Events
    // ------------------------------------------------
    event ProposalCreated(uint256 indexed id, ProposalType pType, address target, uint256 newThr, uint256 deadline);
    event ProposalExecuted(uint256 indexed id);

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
    // Governance proposals
    // -----------------------------------------------

    function proposeAddSigner(address newSigner) external onlySigner {
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.AddSigner;
        p.target = newSigner;
        p.createdAt = block.timestamp;
        p.deadline = block.timestamp + PROPOSAL_DURATION;
        emit ProposalCreated(pid, ProposalType.AddSigner, newSigner, 0, p.deadline);
    }

    function proposeRemoveSigner(address signer) external onlySigner {
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.RemoveSigner;
        p.target = signer;
        p.createdAt = block.timestamp;
        p.deadline = block.timestamp + PROPOSAL_DURATION;
        emit ProposalCreated(pid, ProposalType.RemoveSigner, signer, 0, p.deadline);
    }

    function proposeChangeThreshold(uint256 newThr) external onlySigner {
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.ChangeThreshold;
        p.newThreshold = newThr;
        p.createdAt = block.timestamp;
        p.deadline = block.timestamp + PROPOSAL_DURATION;
        emit ProposalCreated(pid, ProposalType.ChangeThreshold, address(0), newThr, p.deadline);
    }

    function vote(uint256 proposalId) external onlySigner {
        Proposal storage p = proposals[proposalId];
        require(block.timestamp <= p.deadline, "Proposal expired");
        require(!p.voted[msg.sender], "already");
        p.voted[msg.sender] = true;
        p.votes++;
    }

    function executeProposal(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(!p.executed, "done");
        require(block.timestamp <= p.deadline, "Proposal expired");
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
        }

        emit ProposalExecuted(proposalId);
    }

    // ------------------------------------------------
    // View functions for proposals
    // ------------------------------------------------
    function getProposalInfo(uint256 proposalId) external view returns (
        ProposalType pType,
        address target,
        uint256 newThreshold,
        uint256 votes,
        bool executed,
        uint256 createdAt,
        uint256 deadline,
        bool expired
    ) {
        Proposal storage p = proposals[proposalId];
        return (
            p.pType,
            p.target,
            p.newThreshold,
            p.votes,
            p.executed,
            p.createdAt,
            p.deadline,
            block.timestamp > p.deadline
        );
    }

    function hasVoted(uint256 proposalId, address signer) external view returns (bool) {
        return proposals[proposalId].voted[signer];
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