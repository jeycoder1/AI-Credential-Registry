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