// Application.java - Main Spring Boot Application
package com.zkproof.certverifier;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}

// Certificate.java - Certificate Entity
package com.zkproof.certverifier.model;

import java.time.LocalDateTime;

public class Certificate {
    private String id;
    private String holderHash;
    private String issuerName;
    private String certificateType;
    private String degreeLevel;
    private LocalDateTime issueDate;
    private LocalDateTime expiryDate;
    private String blockchainHash;
    private boolean isValid;

    // Constructors
    public Certificate() {}

    public Certificate(String id, String holderHash, String issuerName, 
                      String certificateType, String degreeLevel, 
                      LocalDateTime issueDate, LocalDateTime expiryDate, 
                      String blockchainHash) {
        this.id = id;
        this.holderHash = holderHash;
        this.issuerName = issuerName;
        this.certificateType = certificateType;
        this.degreeLevel = degreeLevel;
        this.issueDate = issueDate;
        this.expiryDate = expiryDate;
        this.blockchainHash = blockchainHash;
        this.isValid = true;
    }

    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }

    public String getHolderHash() { return holderHash; }
    public void setHolderHash(String holderHash) { this.holderHash = holderHash; }

    public String getIssuerName() { return issuerName; }
    public void setIssuerName(String issuerName) { this.issuerName = issuerName; }

    public String getCertificateType() { return certificateType; }
    public void setCertificateType(String certificateType) { this.certificateType = certificateType; }

    public String getDegreeLevel() { return degreeLevel; }
    public void setDegreeLevel(String degreeLevel) { this.degreeLevel = degreeLevel; }

    public LocalDateTime getIssueDate() { return issueDate; }
    public void setIssueDate(LocalDateTime issueDate) { this.issueDate = issueDate; }

    public LocalDateTime getExpiryDate() { return expiryDate; }
    public void setExpiryDate(LocalDateTime expiryDate) { this.expiryDate = expiryDate; }

    public String getBlockchainHash() { return blockchainHash; }
    public void setBlockchainHash(String blockchainHash) { this.blockchainHash = blockchainHash; }

    public boolean isValid() { return isValid; }
    public void setValid(boolean valid) { isValid = valid; }
}

// ZKProof.java - Zero-Knowledge Proof Model
package com.zkproof.certverifier.model;

public class ZKProof {
    private String proofId;
    private String challenge;
    private String response;
    private String commitment;
    private String publicKey;
    private boolean isVerified;

    public ZKProof() {}

    public ZKProof(String proofId, String challenge, String response, 
                   String commitment, String publicKey) {
        this.proofId = proofId;
        this.challenge = challenge;
        this.response = response;
        this.commitment = commitment;
        this.publicKey = publicKey;
        this.isVerified = false;
    }

    // Getters and Setters
    public String getProofId() { return proofId; }
    public void setProofId(String proofId) { this.proofId = proofId; }

    public String getChallenge() { return challenge; }
    public void setChallenge(String challenge) { this.challenge = challenge; }

    public String getResponse() { return response; }
    public void setResponse(String response) { this.response = response; }

    public String getCommitment() { return commitment; }
    public void setCommitment(String commitment) { this.commitment = commitment; }

    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public boolean isVerified() { return isVerified; }
    public void setVerified(boolean verified) { isVerified = verified; }
}

// VerificationRequest.java - Request Model
package com.zkproof.certverifier.model;

public class VerificationRequest {
    private String certificateId;
    private String holderIdentifier;
    private String proofData;
    private String requestedFields;
    private String verifierPublicKey;

    public VerificationRequest() {}

    // Getters and Setters
    public String getCertificateId() { return certificateId; }
    public void setCertificateId(String certificateId) { this.certificateId = certificateId; }

    public String getHolderIdentifier() { return holderIdentifier; }
    public void setHolderIdentifier(String holderIdentifier) { this.holderIdentifier = holderIdentifier; }

    public String getProofData() { return proofData; }
    public void setProofData(String proofData) { this.proofData = proofData; }

    public String getRequestedFields() { return requestedFields; }
    public void setRequestedFields(String requestedFields) { this.requestedFields = requestedFields; }

    public String getVerifierPublicKey() { return verifierPublicKey; }
    public void setVerifierPublicKey(String verifierPublicKey) { this.verifierPublicKey = verifierPublicKey; }
}

// VerificationResponse.java - Response Model
package com.zkproof.certverifier.model;

import java.time.LocalDateTime;
import java.util.Map;

public class VerificationResponse {
    private String verificationId;
    private boolean isValid;
    private boolean zkProofVerified;
    private String status;
    private String message;
    private Map<String, Object> provenFields;
    private LocalDateTime verificationTime;
    private String verifierSignature;

    public VerificationResponse() {}

    public VerificationResponse(String verificationId, boolean isValid, 
                              boolean zkProofVerified, String status, 
                              String message, Map<String, Object> provenFields) {
        this.verificationId = verificationId;
        this.isValid = isValid;
        this.zkProofVerified = zkProofVerified;
        this.status = status;
        this.message = message;
        this.provenFields = provenFields;
        this.verificationTime = LocalDateTime.now();
    }

    // Getters and Setters
    public String getVerificationId() { return verificationId; }
    public void setVerificationId(String verificationId) { this.verificationId = verificationId; }

    public boolean isValid() { return isValid; }
    public void setValid(boolean valid) { isValid = valid; }

    public boolean isZkProofVerified() { return zkProofVerified; }
    public void setZkProofVerified(boolean zkProofVerified) { this.zkProofVerified = zkProofVerified; }

    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }

    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }

    public Map<String, Object> getProvenFields() { return provenFields; }
    public void setProvenFields(Map<String, Object> provenFields) { this.provenFields = provenFields; }

    public LocalDateTime getVerificationTime() { return verificationTime; }
    public void setVerificationTime(LocalDateTime verificationTime) { this.verificationTime = verificationTime; }

    public String getVerifierSignature() { return verifierSignature; }
    public void setVerifierSignature(String verifierSignature) { this.verifierSignature = verifierSignature; }
}