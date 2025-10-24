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
