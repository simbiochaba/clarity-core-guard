;; CoreGuard - Secure Personal Data Management

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-unauthorized (err u100))
(define-constant err-invalid-data (err u101))
(define-constant err-no-data (err u102))
(define-constant err-already-exists (err u103))

;; Data Variables
(define-map user-data { owner: principal } { encrypted-data: (string-utf8 1024) })
(define-map data-permissions { data-owner: principal, accessor: principal } { can-access: bool })
(define-map access-logs { data-owner: principal } { access-count: uint, last-access: uint })

;; Private Functions
(define-private (is-authorized (data-owner principal) (accessor principal))
    (default-to false 
        (get can-access 
            (map-get? data-permissions { data-owner: data-owner, accessor: accessor })
        )
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

(define-public (grant-access (to principal))
    (begin
        (map-set data-permissions
            {data-owner: tx-sender, accessor: to}
            {can-access: true}
        )
        (ok true)
    )
)

(define-public (revoke-access (from principal))
    (begin
        (map-set data-permissions
            {data-owner: tx-sender, accessor: from}
            {can-access: false}
        )
        (ok true)
    )
)

(define-public (access-data (owner principal))
    (let (
        (authorized (is-authorized owner tx-sender))
        (current-time (unwrap-panic (get-block-info? time u0)))
    )
        (if authorized
            (begin
                (map-set access-logs 
                    {data-owner: owner}
                    {
                        access-count: (+ u1 (default-to u0 (get access-count (map-get? access-logs {data-owner: owner})))),
                        last-access: current-time
                    }
                )
                (ok (get encrypted-data (unwrap! (map-get? user-data {owner: owner}) err-no-data)))
            )
            err-unauthorized
        )
    )
)

;; Read Only Functions
(define-read-only (get-access-logs (owner principal))
    (ok (map-get? access-logs {data-owner: owner}))
)

(define-read-only (check-access (owner principal) (accessor principal))
    (ok (is-authorized owner accessor))
)