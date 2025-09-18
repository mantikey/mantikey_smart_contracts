// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract MantiKey is EIP712 {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    // ------------------------------------------------
    // Storage
    // ------------------------------------------------
    address[] public signers;
    mapping(address => bool) public isSigner;
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
    event MultiSendETH(address indexed sender, uint256 totalAmount, uint256 recipients);
    event MultiSendERC20(address indexed sender, address indexed token, uint256 totalAmount, uint256 recipients);

    // ------------------------------------------------
    // Constructor
    // ------------------------------------------------
    constructor(address[3] memory initialSigners, uint256 initialThreshold)
        EIP712("MantiKey", "1")
    {        require(initialThreshold > 0, "invalid threhold");
        for (uint256 i = 0; i < initialSigners.length; i++) {
            require(initialSigners[i] != address(0), "zero");
            require(!isSigner[initialSigners[i]], "duplicated signer");
            signers.push(initialSigners[i]);
            isSigner[initialSigners[i]] = true;
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
        require(!isSigner[newSigner], "already signer");
        require(newSigner != address(0), "zero address");
        
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.AddSigner;
        p.target = newSigner;
        p.createdAt = block.timestamp;
        p.deadline = block.timestamp + PROPOSAL_DURATION;
        emit ProposalCreated(pid, ProposalType.AddSigner, newSigner, 0, p.deadline);
    }

    function proposeRemoveSigner(address signer) external onlySigner {
        require(isSigner[signer], "not a signer");
        require(signers.length > 1, "cannot remove last signer");
        
        uint256 pid = proposalCount++;
        Proposal storage p = proposals[pid];
        p.pType = ProposalType.RemoveSigner;
        p.target = signer;
        p.createdAt = block.timestamp;
        p.deadline = block.timestamp + PROPOSAL_DURATION;
        emit ProposalCreated(pid, ProposalType.RemoveSigner, signer, 0, p.deadline);
    }

    function proposeChangeThreshold(uint256 newThr) external onlySigner {
        require(newThr > 0, "threshold must be > 0");
        require(newThr <= signers.length, "threshold too high");
        
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
        require(!p.voted[msg.sender], "already voted");
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
            signers.push(p.target);
            isSigner[p.target] = true;
        } else if (p.pType == ProposalType.RemoveSigner) {
            _removeSigner(p.target);
        } else if (p.pType == ProposalType.ChangeThreshold) {
            threshold = p.newThreshold;
        }

        emit ProposalExecuted(proposalId);
    }

    // ------------------------------------------------
    // Multisends
    // ------------------------------------------------
    // -------------------------
    /// ETH multisend
    /// -------------------------
    /// @param recipients list of recipients
    /// @param amounts list of ETH amounts per recipient
    /// @param pullFromSender if true, ETH must be sent in msg.value;
    ///        if false, ETH comes from the contract’s existing balance
    function multisendETH(
        address[] calldata recipients,
        uint256[] calldata amounts,
        bool pullFromSender
    ) external payable {
        uint256 len = recipients.length;
        require(len > 0, "No recipients");
        require(len == amounts.length, "Length mismatch");

        uint256 computedTotal = 0;
        for (uint256 i = 0; i < len; ) {
            computedTotal += amounts[i];
            unchecked { ++i; }
        }

        if (pullFromSender) {
            require(msg.value == computedTotal, "Incorrect msg.value");
        } else {
            require(address(this).balance >= computedTotal, "Insufficient contract ETH");
        }

        for (uint256 i = 0; i < len; ) {
            uint256 value = amounts[i];
            if (value > 0) {
                (bool ok, ) = payable(recipients[i]).call{value: value}("");
                require(ok, "ETH transfer failed");
            }
            unchecked { ++i; }
        }

        emit MultiSendETH(msg.sender, computedTotal, len);
    }

    /// -------------------------
    /// ERC20 multisend
    /// -------------------------
    /// @param token ERC20 token
    /// @param recipients list of recipients
    /// @param amounts list of amounts per recipient
    /// @param pullFromSender if true, pulls tokens from msg.sender via transferFrom;
    ///        if false, sends from the contract’s balance
    function multisendERC20(
        IERC20 token,
        address[] calldata recipients,
        uint256[] calldata amounts,
        bool pullFromSender
    ) external {
        uint256 len = recipients.length;
        require(len > 0, "No recipients");
        require(len == amounts.length, "Length mismatch");

        uint256 computedTotal = 0;
        for (uint256 i = 0; i < len; ) {
            computedTotal += amounts[i];
            unchecked { ++i; }
        }

        if (pullFromSender) {
            for (uint256 i = 0; i < len; ) {
                uint256 value = amounts[i];
                if (value > 0) {
                    token.safeTransferFrom(msg.sender, recipients[i], value);
                }
                unchecked { ++i; }
            }
        } else {
            for (uint256 i = 0; i < len; ) {
                uint256 value = amounts[i];
                if (value > 0) {
                    token.safeTransfer(recipients[i], value);
                }
                unchecked { ++i; }
            }
        }

        emit MultiSendERC20(msg.sender, address(token), computedTotal, len);
    }

    // ------------------------------------------------
    // Internal helper to remove signer
    // ------------------------------------------------
    function _removeSigner(address signer) internal {
        isSigner[signer] = false;
        
        // Find the signer in the array and remove it
        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == signer) {
                // Move the last element to this position and pop
                signers[i] = signers[signers.length - 1];
                signers.pop();
                break;
            }
        }
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
    // View all signers
    // ------------------------------------------------
    function getAllSigners() external view returns (address[] memory) {
        return signers;
    }

    // ------------------------------------------------
    // Getter for signer count
    // ------------------------------------------------
    function signerCount() external view returns (uint256) {
        return signers.length;
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