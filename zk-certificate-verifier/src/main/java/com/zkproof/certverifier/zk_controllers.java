// CertificateVerificationController.java - REST API Controller
package com.zkproof.certverifier.controller;

import com.zkproof.certverifier.model.*;
import com.zkproof.certverifier.service.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/certificates")
@CrossOrigin(origins = "*")
public class CertificateVerificationController {
    
    @Autowired
    private CertificateVerificationService verificationService;
    
    @Autowired
    private ZKProofService zkProofService;
    
    @Autowired
    private CertificateService certificateService;
    
    @Autowired
    private BlockchainService blockchainService;
    
    /**
     * Main endpoint for ZK-proof based certificate verification
     */
    @PostMapping("/verify")
    public ResponseEntity<VerificationResponse> verifyWithZKProof(
            @RequestBody VerificationRequest request) {
        try {
            VerificationResponse response = verificationService.verifyWithZKProof(request);
            
            if (response.isValid()) {
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.badRequest().body(response);
            }
        } catch (Exception e) {
            VerificationResponse errorResponse = new VerificationResponse(
                "ERROR_" + System.currentTimeMillis(), false, false, 
                "SYSTEM_ERROR", "Internal server error: " + e.getMessage(), null
            );
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(errorResponse);
        }
    }
    
    /**
     * Batch verification endpoint
     */
    @PostMapping("/verify/batch")
    public ResponseEntity<List<VerificationResponse>> batchVerify(
            @RequestBody List<VerificationRequest> requests) {
        try {
            List<VerificationResponse> responses = verificationService.batchVerification(requests);
            return ResponseEntity.ok(responses);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * Quick verification without ZK proof (basic blockchain check)
     */
    @GetMapping("/quick-verify/{certificateId}")
    public ResponseEntity<VerificationResponse> quickVerify(
            @PathVariable String certificateId,
            @RequestParam String blockchainHash) {
        try {
            VerificationResponse response = verificationService
                .quickVerify(certificateId, blockchainHash);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * Get certificate metadata (public information only)
     */
    @GetMapping("/{certificateId}/metadata")
    public ResponseEntity<Map<String, Object>> getCertificateMetadata(
            @PathVariable String certificateId) {
        try {
            Map<String, Object> metadata = certificateService
                .getCertificateMetadata(certificateId);
            
            if (metadata != null) {
                return ResponseEntity.ok(metadata);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * Get blockchain record for certificate
     */
    @GetMapping("/{certificateId}/blockchain")
    public ResponseEntity<Map<String, Object>> getBlockchainRecord(
            @PathVariable String certificateId) {
        try {
            Map<String, Object> record = blockchainService
                .getBlockchainRecord(certificateId);
            
            if (record != null) {
                return ResponseEntity.ok(record);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * Generate ZK proof challenge
     */
    @PostMapping("/generate-challenge")
    public ResponseEntity<Map<String, String>> generateChallenge() {
        try {
            String challenge = zkProofService.generateChallenge();
            return ResponseEntity.ok(Map.of(
                "challenge", challenge,
                "timestamp", String.valueOf(System.currentTimeMillis()),
                "validUntil", String.valueOf(System.currentTimeMillis() + 300000) // 5 minutes
            ));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
    
    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> health = Map.of(
            "status", "UP",
            "timestamp", System.currentTimeMillis(),
            "services", Map.of(
                "zkProofService", "operational",
                "blockchainService", "operational",
                "certificateService", "operational"
            )
        );
        return ResponseEntity.ok(health);
    }
    
    /**
     * Get verification analytics
     */
    @GetMapping("/analytics")
    public ResponseEntity<Map<String, Object>> getAnalytics() {
        try {
            Map<String, Object> analytics = verificationService.getVerificationAnalytics();
            return ResponseEntity.ok(analytics);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}

// WebController.java - Web UI Controller
package com.zkproof.certverifier.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class WebController {
    
    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("title", "ZK-Proof Certificate Verifier");
        return "index";
    }
    
    @GetMapping("/verify")
    public String verifyPage(Model model) {
        model.addAttribute("title", "Verify Certificate");
        return "verify";
    }
    
    @GetMapping("/admin")
    public String adminPage(Model model) {
        model.addAttribute("title", "Admin Dashboard");
        return "admin";
    }
    
    @GetMapping("/help")
    public String helpPage(Model model) {
        model.addAttribute("title", "Help & Documentation");
        return "help";
    }
}

// ExceptionController.java - Global Exception Handler
package com.zkproof.certverifier.controller;

import com.zkproof.certverifier.model.VerificationResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class ExceptionController {
    
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(
            IllegalArgumentException ex, WebRequest request) {
        
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", LocalDateTime.now());
        errorDetails.put("status", HttpStatus.BAD_REQUEST.value());
        errorDetails.put("error", "Bad Request");
        errorDetails.put("message", ex.getMessage());
        errorDetails.put("path", request.getDescription(false));
        
        return new ResponseEntity<>(errorDetails, HttpStatus.BAD_REQUEST);
    }
    
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<Map<String, Object>> handleRuntimeException(
            RuntimeException ex, WebRequest request) {
        
        Map<String, Object> errorDetails = new HashMap<>();
        errorDetails.put("timestamp", LocalDateTime.now());
        errorDetails.put("status", HttpStatus.INTERNAL_SERVER_ERROR.value());
        errorDetails.put("error", "Internal Server Error");
        errorDetails.put("message", "An unexpected error occurred");
        errorDetails.put("path", request.getDescription(false));
        
        return new ResponseEntity<>(errorDetails, HttpStatus.INTERNAL_SERVER_ERROR);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<VerificationResponse> handleGenericException(
            Exception ex, WebRequest request) {
        
        VerificationResponse errorResponse = new VerificationResponse(
            "ERROR_" + System.currentTimeMillis(),
            false, false, "SYSTEM_ERROR",
            "System error: " + ex.getMessage(), null
        );
        
        return new ResponseEntity<>(errorResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}