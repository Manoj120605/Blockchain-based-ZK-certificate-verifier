// CertificateVerificationService.java - Main Verification Service
package com.zkproof.certverifier.service;

import com.zkproof.certverifier.model.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class CertificateVerificationService {
    
    @Autowired
    private ZKProofService zkProofService;
    
    @Autowired
    private CertificateService certificateService;
    
    @Autowired
    private BlockchainService blockchainService;
    
    /**
     * Main verification method using Zero-Knowledge Proofs
     */
    public VerificationResponse verifyWithZKProof(VerificationRequest request) {
        try {
            String verificationId = generateVerificationId();
            
            // Step 1: Validate basic request
            if (!isValidRequest(request)) {
                return new VerificationResponse(
                    verificationId, false, false, "INVALID_REQUEST",
                    "Invalid verification request parameters", null
                );
            }
            
            // Step 2: Get certificate metadata (without sensitive data)
            Map<String, Object> certMetadata = certificateService
                .getCertificateMetadata(request.getCertificateId());
            
            if (certMetadata == null) {
                return new VerificationResponse(
                    verificationId, false, false, "CERTIFICATE_NOT_FOUND",
                    "Certificate not found in the system", null
                );
            }
            
            // Step 3: Validate certificate on blockchain
            Optional<Certificate> cert = certificateService
                .getCertificateById(request.getCertificateId());
            
            if (!cert.isPresent()) {
                return new VerificationResponse(
                    verificationId, false, false, "BLOCKCHAIN_VALIDATION_FAILED",
                    "Certificate not found on blockchain", null
                );
            }
            
            boolean blockchainValid = blockchainService.validateOnBlockchain(
                request.getCertificateId(), cert.get().getBlockchainHash()
            );
            
            if (!blockchainValid) {
                return new VerificationResponse(
                    verificationId, false, false, "BLOCKCHAIN_VALIDATION_FAILED",
                    "Certificate validation failed on blockchain", null
                );
            }
            
            // Step 4: Parse and verify ZK proof
            ZKProof zkProof = parseZKProofFromRequest(request.getProofData());
            if (zkProof == null) {
                return new VerificationResponse(
                    verificationId, false, false, "INVALID_ZK_PROOF",
                    "Invalid or malformed zero-knowledge proof", null
                );
            }
            
            // Step 5: Verify ZK proof
            boolean zkProofValid = zkProofService.verifyProof(zkProof, cert.get().getBlockchainHash());
            
            if (!zkProofValid) {
                return new VerificationResponse(
                    verificationId, false, false, "ZK_PROOF_VERIFICATION_FAILED",
                    "Zero-knowledge proof verification failed", null
                );
            }
            
            // Step 6: Generate selective disclosure response
            Map<String, Object> provenFields = generateSelectiveDisclosureResponse(
                cert.get(), request.getRequestedFields()
            );
            
            // Step 7: Create successful response
            VerificationResponse response = new VerificationResponse(
                verificationId, true, true, "VERIFIED",
                "Certificate successfully verified with zero-knowledge proof", 
                provenFields
            );
            
            // Step 8: Sign the response
            response.setVerifierSignature(generateVerifierSignature(response));
            
            return response;
            
        } catch (Exception e) {
            return new VerificationResponse(
                generateVerificationId(), false, false, "SYSTEM_ERROR",
                "System error during verification: " + e.getMessage(), null
            );
        }
    }
    
    /**
     * Batch verification for multiple certificates
     */
    public List<VerificationResponse> batchVerification(List<VerificationRequest> requests) {
        return requests.stream()
            .map(this::verifyWithZKProof)
            .collect(Collectors.toList());
    }
    
    /**
     * Quick verification without ZK proof (basic blockchain validation)
     */
    public VerificationResponse quickVerify(String certificateId, String blockchainHash) {
        String verificationId = generateVerificationId();
        
        try {
            boolean isValid = blockchainService.validateOnBlockchain(certificateId, blockchainHash);
            Map<String, Object> metadata = certificateService.getCertificateMetadata(certificateId);
            
            if (isValid && metadata != null) {
                return new VerificationResponse(
                    verificationId, true, false, "VERIFIED",
                    "Certificate verified on blockchain (basic verification)", metadata
                );
            } else {
                return new VerificationResponse(
                    verificationId, false, false, "VERIFICATION_FAILED",
                    "Certificate verification failed", null
                );
            }
        } catch (Exception e) {
            return new VerificationResponse(
                verificationId, false, false, "SYSTEM_ERROR",
                "Error during quick verification", null
            );
        }
    }
    
    /**
     * Get verification history and analytics
     */
    public Map<String, Object> getVerificationAnalytics() {
        Map<String, Object> analytics = new HashMap<>();
        
        // In a real system, this would query a database
        analytics.put("totalVerifications", 1250);
        analytics.put("successfulVerifications", 1180);
        analytics.put("failedVerifications", 70);
        analytics.put("zkProofVerifications", 890);
        analytics.put("averageVerificationTime", "2.3 seconds");
        analytics.put("topIssuers", Arrays.asList(
            "Stanford University", "MIT", "Harvard University"
        ));
        analytics.put("verificationTrends", Map.of(
            "today", 45,
            "thisWeek", 320,
            "thisMonth", 1250
        ));
        
        return analytics;
    }
    
    private boolean isValidRequest(VerificationRequest request) {
        return request != null &&
               request.getCertificateId() != null && !request.getCertificateId().trim().isEmpty() &&
               request.getHolderIdentifier() != null && !request.getHolderIdentifier().trim().isEmpty() &&
               request.getProofData() != null && !request.getProofData().trim().isEmpty();
    }
    
    private ZKProof parseZKProofFromRequest(String proofData) {
        try {
            // In a real implementation, this would parse JSON or other structured format
            // For this example, we'll simulate parsing
            String[] parts = proofData.split(",");
            if (parts.length >= 4) {
                return new ZKProof(
                    "parsed_" + System.currentTimeMillis(),
                    parts[0], // challenge
                    parts[1], // response
                    parts[2], // commitment
                    parts[3]  // public key
                );
            }
        } catch (Exception e) {
            // Log error in real implementation
        }
        return null;
    }
    
    private Map<String, Object> generateSelectiveDisclosureResponse(Certificate cert, 
                                                                   String requestedFields) {
        Map<String, Object> response = new HashMap<>();
        
        if (requestedFields == null || requestedFields.isEmpty()) {
            // Return basic public information
            response.put("certificateExists", true);
            response.put("isValid", cert.isValid());
            response.put("issuerName", cert.getIssuerName());
            return response;
        }
        
        String[] fields = requestedFields.split(",");
        for (String field : fields) {
            field = field.trim().toLowerCase();
            switch (field) {
                case "issuer":
                case "issuername":
                    response.put("issuerName", cert.getIssuerName());
                    break;
                case "type":
                case "certificatetype":
                    response.put("certificateType", cert.getCertificateType());
                    break;
                case "degree":
                case "degreelevel":
                    response.put("degreeLevel", cert.getDegreeLevel());
                    break;
                case "issuedate":
                    response.put("issueDate", cert.getIssueDate());
                    break;
                case "valid":
                case "isvalid":
                    response.put("isValid", cert.isValid());
                    break;
                case "expired":
                    response.put("isExpired", cert.getExpiryDate().isBefore(LocalDateTime.now()));
                    break;
                default:
                    // Field not supported for disclosure
                    break;
            }
        }
        
        return response;
    }
    
    private String generateVerificationId() {
        return "VER_" + System.currentTimeMillis() + "_" + 
               new Random().nextInt(10000);
    }
    
    private String generateVerifierSignature(VerificationResponse response) {
        // In a real implementation, this would use proper cryptographic signing
        try {
            String dataToSign = response.getVerificationId() + 
                              response.isValid() + 
                              response.getVerificationTime();
            
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(dataToSign.getBytes("UTF-8"));
            
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            
            return "SIG_" + hexString.toString().substring(0, 16);
        } catch (Exception e) {
            return "SIG_ERROR";
        }
    }
}