;; CoreGuard - Secure Personal Data Management

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-unauthorized (err u100))
(define-constant err-invalid-data (err u101))
(define-constant err-no-data (err u102))
(define-constant err-already-exists (err u103))
(define-constant err-expired (err u104))
(define-constant err-invalid-batch (err u105))
(define-constant err-empty-data (err u106))
(define-constant err-duplicate-principal (err u107))

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
(define-private (update-access-log (data-owner principal))
  (let ((current-time (unwrap-panic (get-block-info? time u0)))
        (existing-log (default-to 
          { access-count: u0, last-access: u0 } 
          (map-get? access-logs { data-owner: data-owner }))))
    (map-set access-logs
      { data-owner: data-owner }
      { 
        access-count: (+ (get access-count existing-log) u1),
        last-access: current-time 
      }
    )
  )
)

(define-private (is-authorized (data-owner principal) (accessor principal))
  (let ((permission-data (map-get? data-permissions { data-owner: data-owner, accessor: accessor })))
    (match permission-data
      permission (and 
        (get can-access permission)
        (match (get expiration permission)
          expiry (if (< (unwrap-panic (get-block-info? time u0)) expiry)
                  (begin
                    (update-access-log data-owner)
                    true
                  )
                  false
          )
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

(define-private (contains-duplicate (principals (list 50 principal)))
  (let ((len-principals (len principals)))
    (> len-principals (len (as-max-len? (list-unique principals) u50)))
  )
)

;; Public Functions
(define-public (store-data (encrypted-data (string-utf8 1024)))
  (let ((data-length (len encrypted-data)))
    (if (is-eq data-length u0)
      err-empty-data
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
  )
)

[... remaining functions updated with similar improvements ...]
