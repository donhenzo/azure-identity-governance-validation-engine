# This file controls what PowerShell modules are
# downloaded and available to the Function app at runtime.
# Az module is included for Managed Identity auth when deployed.
@{
    'Az' = '12.*'
}