import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * EwAI Omni-Assistant — Off-chain engine for task routing, capability attestation,
 * and execution ledger alignment with EwAI contract state. Hermes-style caduceus routing.
 */
public final class EwAIOmniAssistant {

    public static final String ENGINE_NAME = "EwAI Omni-Assistant";
    public static final String VERSION_TAG = "hermes-caduceus-v1";
    public static final int TASK_QUEUE_CAP = 2048;
    public static final int CAPABILITY_SLOTS = 64;
    public static final int EXECUTION_COOLDOWN_BLOCKS = 12;
    public static final int REWARD_BASIS_POINTS = 85;
    public static final long BP_DENOM = 10_000L;
    public static final String DOMAIN_LABEL = "EwAI_OmniAssistant_v1";
    public static final String GOVERNOR_HEX = "0x1F8a3c5E7b9D2f4A6c8e0B2d4F6a8C0e2B4d6F8a0";
    public static final String EXECUTOR_HEX = "0x2A9b4c6D8e0F2a4B6c8D0e2F4a6B8c0D2e4F6a8B";
    public static final String TREASURY_HEX = "0x3B0c5d7E9f1A3b5C7d9E1f3A5b7C9d1E3f5A7b9C";
    public static final String RELAY_HEX = "0x4C1d6e8F0a2B4c6D8e0F2a4B6c8D0e2F4a6B8c0D";
    public static final String ATTESTATION_ORACLE_HEX = "0x5D2e7f9A1b3C5d7E9f1A3b5C7d9E1f3A5b7C9d1E";
    public static final byte SELECTOR_ENQUEUE_TASK = (byte) 0xa1;
    public static final byte SELECTOR_MARK_EXECUTED = (byte) 0xb2;
    public static final byte SELECTOR_ATTEST_CAPABILITY = (byte) 0xc3;
    public static final String KECCAK256_STANDIN = "SHA-256";

    private final long genesisBlock;
    private final String contractAddress;
    private final long chainId;
    private final Instant engineStart;
    private final AtomicLong taskSequence = new AtomicLong(0L);
    private final Map<Long, TaskEntry> taskLedger = new ConcurrentHashMap<>();
    private final Map<Integer, CapabilitySlot> capabilityRegistry = new ConcurrentHashMap<>();
    private final Map<String, Long> executionCountByAddress = new ConcurrentHashMap<>();
    private final List<ExecutionRecord> executionLog = Collections.synchronizedList(new ArrayList<>());
    private final byte[] domainSeparatorSeed;

    public EwAIOmniAssistant(long genesisBlock, String contractAddress, long chainId) {
        this.genesisBlock = genesisBlock;
        this.contractAddress = contractAddress == null ? "" : contractAddress;
        this.chainId = chainId;
        this.engineStart = Instant.now();
        this.domainSeparatorSeed = buildDomainSeparatorSeed();
    }

    private byte[] buildDomainSeparatorSeed() {
        try {
            MessageDigest md = MessageDigest.getInstance(KECCAK256_STANDIN);
            md.update(ByteBuffer.allocate(8).putLong(chainId).array());
            md.update(contractAddress.getBytes(StandardCharsets.UTF_8));
            md.update(DOMAIN_LABEL.getBytes(StandardCharsets.UTF_8));
            md.update(ByteBuffer.allocate(8).putLong(genesisBlock).array());
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Digest unavailable", e);
        }
    }

    /**
     * Compute task hash compatible with EwAI.enqueueTask — keccak256(domainSeparator, payload).
     */
    public String computeTaskHash(byte[] payload) {
        try {
            MessageDigest md = MessageDigest.getInstance(KECCAK256_STANDIN);
            md.update(domainSeparatorSeed);
            if (payload != null) md.update(payload);
            return "0x" + HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Digest unavailable", e);
        }
    }

    /**
     * Compute task hash from string payload (UTF-8 encoded).
     */
    public String computeTaskHash(String payload) {
        return computeTaskHash(payload == null ? null : payload.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Enqueue a task locally (mirrors contract enqueueTask).
     */
    public long enqueueTaskLocal(String taskHashHex, String requesterAddress, int priority) {
        if (taskLedger.size() >= TASK_QUEUE_CAP) {
            throw new IllegalStateException("EwAI_QueueFull");
        }
        long seq = taskSequence.incrementAndGet();
        long enqueuedAt = System.currentTimeMillis();
        TaskEntry entry = new TaskEntry(
                seq,
                taskHashHex,
                requesterAddress,
                enqueuedAt,
                priority,
                false,
                0L
        );
        taskLedger.put(seq, entry);
        return seq;
    }

    /**
     * Mark a task as executed locally (mirrors contract markTaskExecuted).
     */
    public void markTaskExecutedLocal(long taskSequenceId, String executorAddress) {
        TaskEntry entry = taskLedger.get(taskSequenceId);
        if (entry == null) throw new IllegalArgumentException("EwAI_TaskNotFound");
        if (entry.executed) throw new IllegalStateException("EwAI_AlreadyExecuted");
        entry.executed = true;
        entry.executedAtBlock = genesisBlock + executionLog.size();
        executionCountByAddress.merge(executorAddress, 1L, Long::sum);
        executionLog.add(new ExecutionRecord(executorAddress, taskSequenceId, entry.executedAtBlock, Instant.now()));
    }

    /**
     * Attest a capability in a slot (mirrors contract attestCapability).
     */
    public void attestCapabilityLocal(int slotIndex, String capabilityIdHex, String attesterAddress) {
        if (slotIndex < 0 || slotIndex >= CAPABILITY_SLOTS) {
            throw new IllegalArgumentException("EwAI_InvalidCapabilityIndex");
        }
        long attestedAt = System.currentTimeMillis();
        capabilityRegistry.put(slotIndex, new CapabilitySlot(capabilityIdHex, attesterAddress, attestedAt, false));
    }

    /**
     * Revoke a capability slot locally (mirrors contract revokeCapability).
     */
    public void revokeCapabilityLocal(int slotIndex) {
        CapabilitySlot slot = capabilityRegistry.get(slotIndex);
        if (slot == null) return;
        capabilityRegistry.put(slotIndex, new CapabilitySlot(slot.capabilityId, slot.attester, slot.attestedAtBlock, true));
    }

    /**
     * Compute reward for an execution (basis points of base unit).
     */
    public long computeRewardForExecution(long baseUnit) {
        return (baseUnit * REWARD_BASIS_POINTS) / BP_DENOM;
    }

    /**
     * Get current epoch index at a given block number (12-block cooldown windows).
     */
    public long getEpochIndexAtBlock(long blockNumber) {
        if (blockNumber < genesisBlock) return 0L;
        return (blockNumber - genesisBlock) / EXECUTION_COOLDOWN_BLOCKS;
    }

    /**
     * Check whether cooldown has elapsed for a task (by enqueued block).
     */
    public boolean isCooldownElapsed(long enqueuedBlock, long currentBlock) {
        return currentBlock >= enqueuedBlock + EXECUTION_COOLDOWN_BLOCKS;
    }

    public Optional<TaskEntry> getTask(long sequenceId) {
        return Optional.ofNullable(taskLedger.get(sequenceId));
    }

    public Optional<CapabilitySlot> getCapabilitySlot(int index) {
        return Optional.ofNullable(capabilityRegistry.get(index));
    }

    public long getExecutionCountForAddress(String address) {
        return executionCountByAddress.getOrDefault(address, 0L);
    }

    public List<ExecutionRecord> getExecutionLogSnapshot() {
        synchronized (executionLog) {
            return new ArrayList<>(executionLog);
        }
    }

    public int getTaskLedgerSize() {
        return taskLedger.size();
    }

    public int getCapabilityRegistrySize() {
        return capabilityRegistry.size();
    }

    public long getGenesisBlock() { return genesisBlock; }
    public String getContractAddress() { return contractAddress; }
    public long getChainId() { return chainId; }
    public Instant getEngineStart() { return engineStart; }
    public byte[] getDomainSeparatorSeed() { return domainSeparatorSeed.clone(); }

    /**
     * Build calldata selector for enqueueTask(bytes32,address,uint8). First byte placeholder.
     */
    public static byte[] selectorEnqueueTask() {
        return new byte[] { SELECTOR_ENQUEUE_TASK, 0x00, 0x00, 0x00 };
    }

    public static byte[] selectorMarkTaskExecuted() {
        return new byte[] { SELECTOR_MARK_EXECUTED, 0x00, 0x00, 0x00 };
    }

    public static byte[] selectorAttestCapability() {
        return new byte[] { SELECTOR_ATTEST_CAPABILITY, 0x00, 0x00, 0x00 };
    }

    /**
     * Encode capability ID as 32-byte hex for contract (left-padded).
     */
    public static String encodeCapabilityId32(String hex) {
        if (hex == null || hex.isEmpty()) return "0x" + "0".repeat(64);
        String clean = hex.startsWith("0x") ? hex.substring(2) : hex;
        if (clean.length() >= 64) return "0x" + clean.substring(0, 64);
        return "0x" + "0".repeat(64 - clean.length()) + clean;
    }

    // ─── Inner data types ────────────────────────────────────────────────────────

    public static final class TaskEntry {
        public final long sequenceId;
        public final String taskHashHex;
        public final String requesterAddress;
        public final long enqueuedAtMs;
        public final int priority;
        public volatile boolean executed;
        public volatile long executedAtBlock;

        public TaskEntry(long sequenceId, String taskHashHex, String requesterAddress,
                         long enqueuedAtMs, int priority, boolean executed, long executedAtBlock) {
            this.sequenceId = sequenceId;
            this.taskHashHex = taskHashHex;
            this.requesterAddress = requesterAddress;
            this.enqueuedAtMs = enqueuedAtMs;
            this.priority = priority;
            this.executed = executed;
            this.executedAtBlock = executedAtBlock;
        }
    }

    public static final class CapabilitySlot {
        public final String capabilityId;
        public final String attester;
        public final long attestedAtBlock;
        public final boolean revoked;

        public CapabilitySlot(String capabilityId, String attester, long attestedAtBlock, boolean revoked) {
            this.capabilityId = capabilityId;
            this.attester = attester;
            this.attestedAtBlock = attestedAtBlock;
            this.revoked = revoked;
        }
    }

    public static final class ExecutionRecord {
        public final String executorAddress;
        public final long taskSequenceId;
        public final long blockNumber;
        public final Instant timestamp;

        public ExecutionRecord(String executorAddress, long taskSequenceId, long blockNumber, Instant timestamp) {
            this.executorAddress = executorAddress;
            this.taskSequenceId = taskSequenceId;
            this.blockNumber = blockNumber;
            this.timestamp = timestamp;
        }
    }

    // ─── Hermes AI routing helpers ────────────────────────────────────────────────

    /**
     * Priority levels for task routing (aligned with contract uint8 priority).
     */
    public enum TaskPriority {
        LOW(0), NORMAL(1), HIGH(2), URGENT(3);
        public final int code;
        TaskPriority(int code) { this.code = code; }
    }

