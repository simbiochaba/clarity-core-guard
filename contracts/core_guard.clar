;; CoreGuard - Secure Personal Data Management

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-unauthorized (err u100))
(define-constant err-invalid-data (err u101))
(define-constant err-no-data (err u102))
(define-constant err-already-exists (err u103))
(define-constant err-expired (err u104))
(define-constant err-invalid-batch (err u105))

;; Data Variables
(define-map user-data { owner: principal } { encrypted-data: (string-utf8 1024) })
(define-map data-permissions 
  { data-owner: principal, accessor: principal } 
  { can-access: bool, expiration: (optional uint) }
)
(define-map access-logs { data-owner: principal } { access-count: uint, last-access: uint })
(define-map batch-permissions { batch-id: uint } { owner: principal, accessors: (list 50 principal) })

;; Counter for batch IDs
(define-data-var batch-nonce uint u0)

;; Private Functions
(define-private (is-authorized (data-owner principal) (accessor principal))
  (let ((permission-data (map-get? data-permissions { data-owner: data-owner, accessor: accessor })))
    (match permission-data
      permission (and 
        (get can-access permission)
        (match (get expiration permission)
          expiry (< (unwrap-panic (get-block-info? time u0)) expiry)
          true
        )
      )
      false
    )
  )
)

(define-private (grant-single-access (to principal) (expiry (optional uint)))
  (begin
    (map-set data-permissions
      {data-owner: tx-sender, accessor: to}
      {can-access: true, expiration: expiry}
    )
    (ok true)
  )
)

;; Public Functions
(define-public (store-data (encrypted-data (string-utf8 1024)))
  (let ((existing-data (map-get? user-data {owner: tx-sender})))
    (if (is-some existing-data)
      err-already-exists
      (begin
        (map-set user-data 
          {owner: tx-sender} 
          {encrypted-data: encrypted-data}
        )
        (ok true)
      )
    )
  )
)

(define-public (delete-data)
  (let ((existing-data (map-get? user-data {owner: tx-sender})))
    (if (is-none existing-data)
      err-no-data
      (begin
        (map-delete user-data {owner: tx-sender})
        (ok true)
      )
    )
  )
)

(define-public (grant-access (to principal) (expiry (optional uint)))
  (grant-single-access to expiry)
)

(define-public (grant-batch-access (to (list 50 principal)) (expiry (optional uint)))
  (let 
    (
      (batch-id (+ (var-get batch-nonce) u1))
      (accessor-count (len to))
    )
    (if (> accessor-count u0)
      (begin
        (var-set batch-nonce batch-id)
        (map-set batch-permissions
          { batch-id: batch-id }
          { owner: tx-sender, accessors: to }
        )
        (map (lambda (accessor) (grant-single-access accessor expiry)) to)
        (ok batch-id)
      )
      err-invalid-batch
    )
  )
)

[... remaining functions unchanged ...]
