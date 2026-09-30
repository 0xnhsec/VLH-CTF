# AUTH / DefaultCreds — Factory Console (warm-up)

Bug: unchanged default credentials. The appliance was restored to factory
defaults and the `admin` account still ships with its out-of-the-box password
`admin` (documented seed deviation for this warm-up lab).

Why exploitable: the admin panel is properly role-checked — but knowing the
factory credentials *is* the authorized path.

Intended path:
1. Sign in at `/` as `admin` / `admin`.
2. Open `/admin/panel` — the support key holds `DSLTV{AUTH-DefaultCreds-<n>}`.

Flag format: `DSLTV{AUTH-DefaultCreds-<digits>}` — regenerated at every boot.
