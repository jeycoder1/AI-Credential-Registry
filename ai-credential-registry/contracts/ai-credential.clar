;; AICredential Registry
;; Tamper-proof registry for AI certifications and credentials

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u400))
(define-constant err-not-found (err u401))
(define-constant err-not-authorized (err u402))
(define-constant err-already-exists (err u403))
(define-constant err-invalid-issuer (err u404))

;; Data Variables
(define-data-var credential-id-nonce uint u0)

;; Data Maps
(define-map authorized-issuers principal bool)

(define-map credentials
    uint
    {
        holder: principal,
        issuer: principal,
        credential-type: (string-ascii 100),
        credential-hash: (buff 32),
        issue-date: uint,
        expiry-date: uint,
        revoked: bool
    }
)

(define-map holder-credentials
    principal
    (list 50 uint)
)

(define-map issuer-credentials
    principal
    (list 100 uint)
)

;; Public functions
;; #[allow(unchecked_data)]
(define-public (authorize-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (map-set authorized-issuers issuer true)
        (ok true)
    )
)

;; #[allow(unchecked_data)]
(define-public (revoke-issuer (issuer principal))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (map-set authorized-issuers issuer false)
        (ok true)
    )
)

;; Read-only functions
(define-read-only (get-credential (credential-id uint))
    (map-get? credentials credential-id)
)

(define-read-only (is-authorized-issuer (issuer principal))
    (default-to false (map-get? authorized-issuers issuer))
)

(define-read-only (get-holder-credentials (holder principal))
    (default-to (list) (map-get? holder-credentials holder))
)

(define-read-only (get-issuer-credentials (issuer principal))
    (default-to (list) (map-get? issuer-credentials issuer))
)

(define-read-only (verify-credential (credential-id uint) (expected-hash (buff 32)))
    (match (map-get? credentials credential-id)
        credential (and 
            (is-eq (get credential-hash credential) expected-hash)
            (not (get revoked credential))
            (or (is-eq (get expiry-date credential) u0) (< stacks-block-height (get expiry-date credential)))
        )
        false
    )
)

;; #[allow(unchecked_data)]
(define-public (issue-credential 
    (holder principal) 
    (credential-type (string-ascii 100))
    (credential-hash (buff 32))
    (expiry-date uint))
    (let
        ((new-id (var-get credential-id-nonce))
         (holder-creds (get-holder-credentials holder))
         (issuer-creds (get-issuer-credentials tx-sender)))
        (asserts! (is-authorized-issuer tx-sender) err-invalid-issuer)
        (map-set credentials new-id
            {
                holder: holder,
                issuer: tx-sender,
                credential-type: credential-type,
                credential-hash: credential-hash,
                issue-date: stacks-block-height,
                expiry-date: expiry-date,
                revoked: false
            }
        )
        (map-set holder-credentials holder (unwrap-panic (as-max-len? (append holder-creds new-id) u50)))
        (map-set issuer-credentials tx-sender (unwrap-panic (as-max-len? (append issuer-creds new-id) u100)))
        (var-set credential-id-nonce (+ new-id u1))
        (ok new-id)
    )
)

(define-public (revoke-credential (credential-id uint))
    (let
        ((credential (unwrap! (map-get? credentials credential-id) err-not-found)))
        (asserts! (is-eq tx-sender (get issuer credential)) err-not-authorized)
        (map-set credentials credential-id (merge credential {revoked: true}))
        (ok true)
    )
)

;; Additional Data Variables
(define-data-var total-credentials-issued uint u0)
(define-data-var total-revoked-credentials uint u0)
(define-data-var platform-fee uint u100000) ;; 0.1 STX fee for issuing

;; Additional Data Maps
(define-map credential-metadata
    uint
    {
        description: (string-ascii 500),
        achievement-level: (string-ascii 50),
        institution: (string-ascii 200)
    }
)

(define-map issuer-stats
    principal
    {
        total-issued: uint,
        total-revoked: uint,
        active-credentials: uint,
        reputation-score: uint
    }
)

(define-map holder-stats
    principal
    {
        total-received: uint,
        active-count: uint,
        credential-types: (list 20 (string-ascii 100))
    }
)

(define-map credential-endorsements
    uint
    {
        endorsers: (list 10 principal),
        endorsement-count: uint
    }
)

(define-map credential-verification-log
    {credential-id: uint, verifier: principal}
    uint
)

;; Function 1: Get credential with metadata
(define-read-only (get-credential-full (credential-id uint))
    (let
        ((cred (unwrap! (map-get? credentials credential-id) err-not-found))
         (metadata (map-get? credential-metadata credential-id)))
        (ok {
            credential: cred,
            metadata: metadata
        })
    )
)

;; Function 2: Check if credential is valid (not expired and not revoked)
(define-read-only (is-credential-valid (credential-id uint))
    (match (map-get? credentials credential-id)
        credential (ok (and 
            (not (get revoked credential))
            (or (is-eq (get expiry-date credential) u0) 
                (< stacks-block-height (get expiry-date credential)))
        ))
        err-not-found
    )
)

;; Function 3: Get issuer statistics
(define-read-only (get-issuer-stats (issuer principal))
    (ok (default-to 
        {total-issued: u0, total-revoked: u0, active-credentials: u0, reputation-score: u100}
        (map-get? issuer-stats issuer)))
)

;; Function 4: Get holder statistics
(define-read-only (get-holder-stats (holder principal))
    (ok (default-to 
        {total-received: u0, active-count: u0, credential-types: (list)}
        (map-get? holder-stats holder)))
)

;; Function 5: Get platform statistics
(define-read-only (get-platform-stats)
    (ok {
        total-credentials: (var-get credential-id-nonce),
        total-issued: (var-get total-credentials-issued),
        total-revoked: (var-get total-revoked-credentials),
        platform-fee: (var-get platform-fee)
    })
)

;; Function 6: Count active credentials for holder
(define-read-only (count-active-credentials (holder principal))
    (let
        ((holder-creds (get-holder-credentials holder)))
        (ok (len (filter is-credential-active-filter holder-creds)))
    )
)

;; Helper function to check if credential is active
(define-private (is-credential-active-filter (credential-id uint))
    (match (map-get? credentials credential-id)
        credential (and 
            (not (get revoked credential))
            (or (is-eq (get expiry-date credential) u0) 
                (< stacks-block-height (get expiry-date credential)))
        )
        false
    )
)

;; Function 7: Get credentials by type for holder (returns all holder credentials)
(define-read-only (get-credentials-by-type (holder principal) (cred-type (string-ascii 100)))
    (ok (get-holder-credentials holder))
)

;; Helper function to check credential type
(define-private (check-credential-type (target-type (string-ascii 100)) (credential-id uint))
    (match (map-get? credentials credential-id)
        credential (is-eq (get credential-type credential) target-type)
        false
    )
)

;; Function 8: Set platform fee (owner only)
;; #[allow(unchecked_data)]
(define-public (set-platform-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set platform-fee new-fee)
        (ok true)
    )
)

;; Additional Data Variables
(define-data-var total-credentials-issued uint u0)
(define-data-var total-revoked-credentials uint u0)
(define-data-var platform-fee uint u100000) ;; 0.1 STX fee for issuing

;; Additional Data Maps
(define-map credential-metadata
    uint
    {
        description: (string-ascii 500),
        achievement-level: (string-ascii 50),
        institution: (string-ascii 200)
    }
)

(define-map issuer-stats
    principal
    {
        total-issued: uint,
        total-revoked: uint,
        active-credentials: uint,
        reputation-score: uint
    }
)

(define-map holder-stats
    principal
    {
        total-received: uint,
        active-count: uint,
        credential-types: (list 20 (string-ascii 100))
    }
)

(define-map credential-endorsements
    uint
    {
        endorsers: (list 10 principal),
        endorsement-count: uint
    }
)

(define-map credential-verification-log
    {credential-id: uint, verifier: principal}
    uint
)

;; Function 1: Get credential with metadata
(define-read-only (get-credential-full (credential-id uint))
    (let
        ((cred (unwrap! (map-get? credentials credential-id) err-not-found))
         (metadata (map-get? credential-metadata credential-id)))
        (ok {
            credential: cred,
            metadata: metadata
        })
    )
)

;; Function 2: Check if credential is valid (not expired and not revoked)
(define-read-only (is-credential-valid (credential-id uint))
    (match (map-get? credentials credential-id)
        credential (ok (and 
            (not (get revoked credential))
            (or (is-eq (get expiry-date credential) u0) 
                (< stacks-block-height (get expiry-date credential)))
        ))
        err-not-found
    )
)

;; Function 3: Get issuer statistics
(define-read-only (get-issuer-stats (issuer principal))
    (ok (default-to 
        {total-issued: u0, total-revoked: u0, active-credentials: u0, reputation-score: u100}
        (map-get? issuer-stats issuer)))
)

;; Function 4: Get holder statistics
(define-read-only (get-holder-stats (holder principal))
    (ok (default-to 
        {total-received: u0, active-count: u0, credential-types: (list)}
        (map-get? holder-stats holder)))
)

;; Function 5: Get platform statistics
(define-read-only (get-platform-stats)
    (ok {
        total-credentials: (var-get credential-id-nonce),
        total-issued: (var-get total-credentials-issued),
        total-revoked: (var-get total-revoked-credentials),
        platform-fee: (var-get platform-fee)
    })
)

;; Function 6: Count active credentials for holder
(define-read-only (count-active-credentials (holder principal))
    (let
        ((holder-creds (get-holder-credentials holder)))
        (ok (len (filter is-credential-active-filter holder-creds)))
    )
)

;; Helper function to check if credential is active
(define-private (is-credential-active-filter (credential-id uint))
    (match (map-get? credentials credential-id)
        credential (and 
            (not (get revoked credential))
            (or (is-eq (get expiry-date credential) u0) 
                (< stacks-block-height (get expiry-date credential)))
        )
        false
    )
)

;; Function 7: Get credentials by type for holder (returns all holder credentials)
(define-read-only (get-credentials-by-type (holder principal) (cred-type (string-ascii 100)))
    (ok (get-holder-credentials holder))
)

;; Helper function to check credential type
(define-private (check-credential-type (target-type (string-ascii 100)) (credential-id uint))
    (match (map-get? credentials credential-id)
        credential (is-eq (get credential-type credential) target-type)
        false
    )
)

;; Function 8: Set platform fee (owner only)
;; #[allow(unchecked_data)]
(define-public (set-platform-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        (var-set platform-fee new-fee)
        (ok true)
    )
)