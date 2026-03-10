// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title ThreatRegistry
 * @dev Smart contract for immutable threat intelligence storage
 * Stores threat records as NFTs with IPFS metadata
 */
contract ThreatRegistry {
    
    // ==========================================
    // STATE VARIABLES
    // ==========================================
    
    struct ThreatRecord {
        string ipAddressHash;      // SHA256 hash of IP address (privacy)
        string ipfsHash;           // IPFS hash containing full metadata
        uint256 timestamp;         // When threat was first detected
        string attackType;         // Type of attack (SYN FLOOD, etc.)
        string threatLevel;        // malicious, suspicious, clean
        bool isReformed;           // Has IP been reformed?
        uint256 reformedTimestamp; // When IP was marked as reformed
        uint256 captchaAttempts;   // Number of CAPTCHA attempts
        uint256 successfulAccesses;// Number of successful accesses after reform
    }
    
    // Mapping from IP hash to threat records
    mapping(string => ThreatRecord[]) public threatRecords;
    
    // Mapping from IP hash to latest record index
    mapping(string => uint256) public latestRecordIndex;
    
    // Total number of unique IPs in registry
    uint256 public totalThreats;
    
    // Contract owner
    address public owner;
    
    // ==========================================
    // EVENTS
    // ==========================================
    
    event ThreatMinted(
        string indexed ipAddressHash,
        string ipfsHash,
        string attackType,
        string threatLevel,
        uint256 timestamp
    );
    
    event ThreatReformed(
        string indexed ipAddressHash,
        uint256 reformedTimestamp,
        uint256 successfulAccesses
    );
    
    event CaptchaAttempt(
        string indexed ipAddressHash,
        bool success,
        uint256 attemptNumber
    );
    
    // ==========================================
    // MODIFIERS
    // ==========================================
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }
    
    // ==========================================
    // CONSTRUCTOR
    // ==========================================
    
    constructor() {
        owner = msg.sender;
    }
    
    // ==========================================
    // CORE FUNCTIONS
    // ==========================================
    
    /**
     * @dev Mint a new threat NFT
     * @param _ipAddressHash SHA256 hash of the IP address
     * @param _ipfsHash IPFS hash containing threat metadata
     * @param _attackType Type of attack detected
     * @param _threatLevel Severity level (malicious, suspicious, clean)
     */
    function mintThreat(
        string memory _ipAddressHash,
        string memory _ipfsHash,
        string memory _attackType,
        string memory _threatLevel
    ) public onlyOwner {
        
        // Create new threat record
        ThreatRecord memory newRecord = ThreatRecord({
            ipAddressHash: _ipAddressHash,
            ipfsHash: _ipfsHash,
            timestamp: block.timestamp,
            attackType: _attackType,
            threatLevel: _threatLevel,
            isReformed: false,
            reformedTimestamp: 0,
            captchaAttempts: 0,
            successfulAccesses: 0
        });
        
        // Check if this is first record for this IP
        if (threatRecords[_ipAddressHash].length == 0) {
            totalThreats++;
        }
        
        // Add to records
        threatRecords[_ipAddressHash].push(newRecord);
        latestRecordIndex[_ipAddressHash] = threatRecords[_ipAddressHash].length - 1;
        
        // Emit event
        emit ThreatMinted(
            _ipAddressHash,
            _ipfsHash,
            _attackType,
            _threatLevel,
            block.timestamp
        );
    }
    
    /**
     * @dev Update reformed status for an IP
     * @param _ipAddressHash SHA256 hash of the IP address
     * @param _isReformed Whether IP is reformed
     */
    function updateReformedStatus(
        string memory _ipAddressHash,
        bool _isReformed
    ) public onlyOwner {
        require(threatRecords[_ipAddressHash].length > 0, "IP not found in registry");
        
        uint256 index = latestRecordIndex[_ipAddressHash];
        ThreatRecord storage record = threatRecords[_ipAddressHash][index];
        
        record.isReformed = _isReformed;
        
        if (_isReformed) {
            record.reformedTimestamp = block.timestamp;
            emit ThreatReformed(
                _ipAddressHash,
                block.timestamp,
                record.successfulAccesses
            );
        }
    }
    
    /**
     * @dev Log a CAPTCHA attempt
     * @param _ipAddressHash SHA256 hash of the IP address
     * @param _success Whether CAPTCHA was successful
     */
    function logCaptchaAttempt(
        string memory _ipAddressHash,
        bool _success
    ) public onlyOwner {
        require(threatRecords[_ipAddressHash].length > 0, "IP not found in registry");
        
        uint256 index = latestRecordIndex[_ipAddressHash];
        ThreatRecord storage record = threatRecords[_ipAddressHash][index];
        
        record.captchaAttempts++;
        
        if (_success) {
            record.successfulAccesses++;
            
            // Auto-reform after 3 successful accesses
            if (record.successfulAccesses >= 3 && !record.isReformed) {
                record.isReformed = true;
                record.reformedTimestamp = block.timestamp;
                
                emit ThreatReformed(
                    _ipAddressHash,
                    block.timestamp,
                    record.successfulAccesses
                );
            }
        }
        
        emit CaptchaAttempt(_ipAddressHash, _success, record.captchaAttempts);
    }
    
    // ==========================================
    // QUERY FUNCTIONS
    // ==========================================
    
    /**
     * @dev Get latest threat record for an IP
     * @param _ipAddressHash SHA256 hash of the IP address
     */
    function getLatestRecord(string memory _ipAddressHash) 
        public 
        view 
        returns (ThreatRecord memory) 
    {
        require(threatRecords[_ipAddressHash].length > 0, "IP not found in registry");
        uint256 index = latestRecordIndex[_ipAddressHash];
        return threatRecords[_ipAddressHash][index];
    }
    
    /**
     * @dev Get all records for an IP
     * @param _ipAddressHash SHA256 hash of the IP address
     */
    function getAllRecords(string memory _ipAddressHash) 
        public 
        view 
        returns (ThreatRecord[] memory) 
    {
        return threatRecords[_ipAddressHash];
    }
    
    /**
     * @dev Check if IP is in registry
     * @param _ipAddressHash SHA256 hash of the IP address
     */
    function isIPInRegistry(string memory _ipAddressHash) 
        public 
        view 
        returns (bool) 
    {
        return threatRecords[_ipAddressHash].length > 0;
    }
    
    /**
     * @dev Get total number of records for an IP
     * @param _ipAddressHash SHA256 hash of the IP address
     */
    function getRecordCount(string memory _ipAddressHash) 
        public 
        view 
        returns (uint256) 
    {
        return threatRecords[_ipAddressHash].length;
    }
    
    /**
     * @dev Get time since last detection
     * @param _ipAddressHash SHA256 hash of the IP address
     */
    function getTimeSinceDetection(string memory _ipAddressHash) 
        public 
        view 
        returns (uint256) 
    {
        require(threatRecords[_ipAddressHash].length > 0, "IP not found in registry");
        uint256 index = latestRecordIndex[_ipAddressHash];
        return block.timestamp - threatRecords[_ipAddressHash][index].timestamp;
    }
}
