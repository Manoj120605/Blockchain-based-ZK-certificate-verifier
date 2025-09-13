# Blockchain-based-ZK-certificate-verifier
ZK-Proof Certificate Verifier — A blockchain-based system for privacy-preserving digital credential verification using Zero-Knowledge Proofs. Verify certificates without exposing sensitive data. Built with Spring Boot, Web3j, and BouncyCastle. Includes selective disclosure and instant validation.
Based on the files provided, here is a description for your GitHub README.md file.

***

---

### Key Features ✨

* [cite_start]**ZK-Proof Verification**: The core of the system verifies the authenticity and ownership of digital certificates using zero-knowledge proofs, ensuring privacy and security[cite: 19].
* [cite_start]**Blockchain Integration**: Certificates are anchored to a blockchain (specifically, the Ethereum testnet) to ensure immutability and prevent tampering[cite: 6]. [cite_start]The application uses `web3j` for interacting with the blockchain[cite: 11].
* [cite_start]**Selective Disclosure**: Users can generate selective disclosure proofs to reveal only specific fields of their certificate (e.g., degree level) without exposing other personal data[cite: 19].
* [cite_start]**RESTful API**: The application exposes a REST API for certificate verification, batch verification, and metadata retrieval[cite: 18].
* [cite_start]**Web Interface**: A modern, responsive web interface is included for easy interaction with the verification service[cite: 20].
* [cite_start]**Security**: The system incorporates `Spring Security` for authentication and access control[cite: 6].
* [cite_start]**Database**: It uses an in-memory `H2` database for development and demonstration purposes, with `Spring Data JPA` for data persistence[cite: 6, 11].

---

### Tech Stack 🛠️

* **Backend**: Java 17, Spring Boot, Spring Security, Spring Data JPA
* **Blockchain**: Ethereum Testnet, `web3j`
* [cite_start]**Cryptography**: `Bouncy Castle` [cite: 11]
* **Database**: H2
* **Frontend**: HTML, Thymeleaf, CSS
* [cite_start]**Build Tool**: Apache Maven [cite: 11]

---

### Getting Started ⚙️

1.  **Clone the repository**: `git clone https://github.com/Manoj120605/Blockchain-based-ZK-certificate-verifier.git`
2.  **Navigate to the project directory**: `cd `
3.  **Run the application**: `mvn spring-boot:run`

[cite_start]The application will be accessible at `http://localhost:8080`[cite: 6]. [cite_start]You can access the H2 console at `http://localhost:8080/h2-console` and the API documentation at `http://localhost:8080/swagger-ui.html`[cite: 6].
