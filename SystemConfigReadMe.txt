Intune AutoPackager System Configuration Reference
Location: AutoPackager.config.json (same folder as the script)
All keys are optional unless marked Required. When a key is missing, the script applies a safe default or built-in behavior. Paths may be absolute or relative to the script directory unless stated otherwise.

1) Paths
- WorkingRoot (string)
  Purpose: Root folder where working artifacts are produced (publisher/app/version, scripts, outputs, CSVs, archives of previous logs).
  Default: "Working"
  Examples:
    - "Working"
    - "D:\\Intune\\AutoPackager\\Working"
- LogPath (string)
  Purpose: Main runtime log file path. On each run, the active log is rotated into the Working folder with a timestamp.
  Default: "AutoPackager.log"
  Examples:
    - "AutoPackager.log"
    - ".\\Logs\\AutoPackager.log"
- RecipesRoot (string)
  Purpose: Folder where application recipe JSON files are stored. Used when -PathRecipes is omitted to locate recipes and optionally prompt for selection.
  Default: "Recipes"
- IntuneWinAppUtil (string | null)
  Purpose: Optional path to IntuneWinAppUtil.exe. If null/omitted, the script looks next to itself and then on PATH.
  Examples:
    - "IntuneWinAppUtil.exe" (next to script)
    - "C:\\Tools\\IntuneWinAppUtil.exe"
    - null (let the script auto-resolve)
- DefaultIconFolder (string)
  Purpose: Folder containing default app icon files. When a recipe does not specify an icon, the script looks here for a matching file.
  Default: "Logos"
  Example: "Logos"
- RecipeNetworkFolder (string)
  Purpose: Optional network/UNC path from which recipe JSON files are synced or pulled at runtime. Leave empty to use only the local RecipesRoot.
  Default: "" (disabled)
  Example: "\\\\server\\share\\Recipes"
- TestingRoot (string)
  Purpose: Root folder for testing artifacts (used during test/dry-run packaging flows).
  Default: "Testing"
- LogFilePathAdmin (string)
  Purpose: Log folder path baked into generated ADT/PSAppDeployToolkit install scripts for the admin (SYSTEM) context. Written into config.psd1 as LogPath.
  Default: "C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\Apps"
- LogFilePathUser (string)
  Purpose: Log folder path baked into generated ADT/PSAppDeployToolkit install scripts for the user context. Written into config.psd1 as LogPathNoAdminRights.
  Default: "C:\\ProgramData\\Logs\\Software"

2) Branding
- NotificationBrandTitle (string)
  Purpose: Prefix shown in user notification pop-ups during install. Also written as CompanyName into PSAppDeployToolkit config.psd1.
  Default: "Your Company"
  Example: "Contoso IT"

3) Email
- Provider (string)
  Purpose: Selects the email send method.
  Allowed: "smtp" | "graph"
  Default: "smtp" (if omitted)
  Notes: When set to "graph", the script uses the Email.Graph object for authentication and ignores Email.Smtp credentials. The sender address is taken from Email.Graph.MailSendMailbox instead of Email.From/Email.Smtp.From.
- Enabled (bool) [optional]
  Purpose: Master enable switch for summary email sending.
  Default: true (if omitted)
- To (string[])
  Purpose: Recipient list for summary email.
  Required: Must be present to send mail.
- From (string)
  Purpose: Sender address when using the "smtp" provider. For "graph" provider, sender is Email.Graph.MailSendMailbox instead.
  Required: Must be present when using smtp provider to send mail.
- SubjectPrefix (string)
  Purpose: Subject prefix for summary emails.
  Default: "Intune AutoPackager"
- AttachCsv (bool)
  Purpose: Attach Summary_*.csv generated in the Working folder.
  Default: false
- AttachLog (bool)
  Purpose: Attach the run log (copied to Working first) when failures are present.
  Default: true
- SendPolicy (string)
  Purpose: Controls when to send email.
  Allowed: "always" | "updatesOrFailures" | "failuresOnly" | "never"
  Default: "updatesOrFailures"
  Behavior:
    - always: Send after every run (if To/From/Smtp present)
    - updatesOrFailures: Send only if at least one app was updated or a failure occurred
    - failuresOnly: Send only if failures occurred
    - never: Do not send email
- Smtp (object) [used when Provider = "smtp"]
  - Server (string) [Required to send]
  - Port (int) [Required to send]
  - From (string) [sender address; can be here or at Email.From]
  - UseSsl (bool) [Required to send]
  - User (string) [Optional; typical for SendGrid is "apikey"]
  - ApiKeyEnv (string) [Optional; e.g., "SENDGRID_API_KEY"]
  - ApiKey (string) [Optional; plaintext API key. Preferred over Password when both set]
  - Password (string) [Optional; plaintext SMTP password]
    Secret sourcing precedence:
      1) Email.Smtp.ApiKey (if set) else Email.Smtp.Password
      2) Environment variable named by Email.Smtp.ApiKeyEnv
      3) Environment variable SENDGRID_API_KEY
    Security note: Storing secrets in JSON is plaintext. Prefer environment variables or a secret store in production. Example for SendGrid:
      User: "apikey"
      Env var: SENDGRID_API_KEY=<your key>
- Graph (object) [used when Provider = "graph"]
  Purpose: App registration credentials for sending mail via Microsoft Graph API (client_credentials flow).
  - TenantId (string) [Required for graph send]
  - ClientId (string) [Required for graph send]
  - ClientSecret (string) [Required for graph send; plaintext, converted to SecureString at runtime]
  - MailSendMailbox (string) [Required for graph send; the shared/licensed mailbox to send from]
  - Scope (string) [Optional; default: "https://graph.microsoft.com/.default"]
  - GrantType (string) [Optional; default: "client_credentials"]
  Security note: Avoid storing ClientSecret in plaintext. Use a secret store or environment injection in production.

4) AzureAuth 
- Purpose: Provide app-only authentication parameters for Intune Graph connections via config.
- Fields:
  - TenantId (string)
  - ClientId (string)
  - ClientSecret (string; plaintext in config; converted to SecureString at runtime)
  - CertificateThumbprint (string; for certificate-based auth from local cert store)
- Precedence with other sources: CLI parameters > Config.AzureAuth > AZInfo.csv
- Auth mode: Provide either ClientSecret or CertificateThumbprint. If both are present, ClientSecret is used.
- Security note: Avoid storing secrets in plaintext when possible. Prefer certificate auth or environment-based secret injection.
- Icon upload: The GUI's IntuneAppTools helper only supports large icon upload when authenticated with a ClientSecret (app-only token). When using certificate-only/module session, icon upload is not performed and a warning is printed.
- Supported icon types for upload: .png, .jpg, .jpeg

5) GitHubToken
- Purpose: Remove API rate limit restrictions when querying GitHub repositories (e.g., winget-pkgs manifest lookups).
- Fields:
  - GitHubToken (string) — personal access token or fine-grained PAT with read access

6) PackagingDefaults
- PreferArchitecture (string)
  Purpose: Preferred installer architecture when multiple are available.
  Allowed: "x64" | "x86" | "arm64"
  Default: "x64"
- DefaultScope (string)
  Purpose: Default winget scope used for metadata queries if recipe does not specify.
  Allowed: "machine" | "user"
  Default: "machine"
- WingetSource (string)
  Purpose: Winget source name for queries.
  Default: "winget"
  Examples: "winget", "msstore"
- RunMode (string)
  Purpose: Default run mode when neither -FullRun nor -PackageOnly is specified on the CLI.
  Allowed: "FullRun" | "PackageOnly"
  Default: "PackageOnly"
- AllRecipes (bool)
  Purpose: When FullRun + no PathRecipes is provided, process all recipes in RecipesRoot instead of prompting for one.
  Default: false
- UpdateDetection (bool)
  Purpose: Default behavior for updating the detection script/rule. When false, behaves as if -NoUpdateDetection was set.
  Default: true
- UseScriptCommandLines (bool)
  Purpose: If true, install/uninstall command lines uploaded to Intune are set to run the generated "install.ps1" and "uninstall.ps1" (preferred). If false, vendor command lines are used instead.
  Default: true

7) AllowAvailableUninstall (bool) [top-level]
- Purpose: When true, enables an uninstall assignment to be created for apps that are deployed as Available (in addition to or instead of Required). When false, uninstall assignments are skipped for Available-intent apps.
- Default: false

8) IntuneUploadVerify
Controls the post-upload verification logic (module-based size/committedContentVersion comparison).
- TimeoutSeconds (int)
  Purpose: Max time to wait for Intune to reflect the new content update.
  Default: 600
- IntervalSeconds (int)
  Purpose: Poll interval during verification.
  Default: 10
- SkipVerify (bool)
  Purpose: If true, skip verification step.
  Default: false
- StrictVerify (bool)
  Purpose: If true, fail the run when verification does not converge.
  Default: false
- SizeTolerancePercent (int)
  Purpose: Accept difference tolerance between module-reported size and local .intunewin size when verifying.
  Default: 5

9) Notification
Defaults used when generating the install.ps1 that runs on endpoints. The popup appears only if:
- Notification.Defaults.Enabled is true (or recipe overrides enable), AND
- There are processes to close (from the recipe ForceTaskClose list) that are currently running.
- Notification popups honor a deferral window, computed from the script generation timestamp in install.ps1.

- Defaults.Enabled (bool)
  Purpose: Enable/disable user notification popups by default (recipe can override).
  Default: false
- Defaults.TimerMinutes (int)
  Purpose: How long the popup waits before auto-continue (in minutes).
  Default: 2
- Defaults.DeferralEnabled (bool)
  Purpose: Allow users to defer within a time window. (Computed at runtime inside install.ps1)
  Default: false
- Defaults.DeferralHoursAllowed (int)
  Purpose: Hours until deferral expires. When expired, popup informs user that installation must occur.
  Default: 24

10) SecondaryRequiredApp
Settings for a secondary app scenario (e.g., "Required Updates" ring).
Note: The script also supports an alternate top-level "Secondary" object with matching structure; if both are present, "SecondaryRequiredApp" takes precedence.

- DisplayNameSuffix (string)
  Purpose: Suffix appended to the secondary app display name on publish (e.g., " - Required Update").
  Default: " - Required Update"
- AssignmentDefaults (object)
  - Intent (string)
    Purpose: Assignment intent used for ring assignments.
    Allowed: "required" (typical)
    Default: "required"
  - Notifications (string)
    Purpose: User notifications policy for Win32 LOB app.
    Common: "showAll", "showReboot", "hideAll" (values passed through to Graph)
    Default: "showAll"
  - DeliveryOptimizationPriority (string)
    Purpose: DO priority for assignments.
    Common: "notConfigured", "foreground", "foregroundPriority"
    Default: "notConfigured"
  - ClearExistingBeforeAssign (bool)
    Purpose: When true, existing assignments are cleared before creating new ring assignments.
    Default: true
  - Deadline (object)
    Purpose: Local deadline time for each ring (date computed as Now + ring delay days + time-of-day below).
    Fields:
      - HourOfDay (int, 0-23)
      - MinuteOfHour (int, 0-59)
    Default: 23:59 local

11) Primary (object) [optional]
Settings for primary app assignment defaults. Used to control deadline behavior on the primary (Available/Required) app separate from the secondary ring app.
- AssignmentDefaults (object)
  - UpdateDeadlineFromRings (bool)
    Purpose: When true, the primary app deadline is updated to match the earliest ring deadline computed this run.
    Default: false
  - Deadline (object)
    Purpose: Explicit deadline time for the primary app assignment.
    Fields:
      - HourOfDay (int, 0-23)
      - MinuteOfHour (int, 0-59)
    Default: 23:59 local

12) RequiredUpdateDefaultGroups
Default Entra group and filter assignments for each deployment ring when publishing a Required Update secondary app. These are used when the recipe does not specify ring group overrides. Ring delay days control when each ring's deadline is set relative to the publish date.

- PilotGroup (string)
  Purpose: Entra group ID or display name for the Pilot (Ring 1) ring assignment.
  Default: "" (no assignment)
- PilotFilter (string)
  Purpose: Intune assignment filter ID or display name for Pilot ring.
  Default: "" (no filter)
- PilotFilterType (string)
  Purpose: Filter inclusion mode for Pilot ring.
  Allowed: "Include" | "Exclude"
  Default: "Include"
- PilotDelayDays (int)
  Purpose: Days after publish date before Pilot ring deadline.
  Default: 1
- UATGroup (string)
  Purpose: Entra group ID or display name for the UAT (Ring 2) ring assignment.
  Default: ""
- UATFilter (string)
  Purpose: Intune assignment filter for UAT ring.
  Default: ""
- UATFilterType (string)
  Allowed: "Include" | "Exclude"
  Default: "Include"
- UATDelayDays (int)
  Purpose: Days after publish date before UAT ring deadline.
  Default: 5
- GAGroup (string)
  Purpose: Entra group ID or display name for the GA (Ring 3) broad deployment ring.
  Default: ""
- GAFilter (string)
  Purpose: Intune assignment filter for GA ring.
  Default: ""
- GAFilterType (string)
  Allowed: "Include" | "Exclude"
  Default: "Include"
- GADelayDays (int)
  Purpose: Days after publish date before GA ring deadline.
  Default: 9

13) Archive
Controls end-of-run archival and retention.
- Enabled (bool)
  Purpose: Enable archive-to-network step. When disabled, archival is skipped.
  Default: true
- NetworkArchiveRoot (string)
  Purpose: Destination root path (UNC/local) for copying Working subfolders at the end of the run.
  Example: "\\\\server\\share\\AutoPackagerArchive"
- RetentionDays (int)
  Purpose: Retention window for cleaning older Summary_*.csv, AutoPackager_*.log in Working and IntuneWinAppUtil logs under Working (stdout/stderr).
  Default: 14
- KeepVersionsPerApp (int)
  Purpose: At the archive root, keep only N newest version folders per app touched this run (older versions are removed).
  Default: 3

14) Cleanup
- PurgeWorkingOnStart (bool)
  Purpose: On start, delete all subfolders inside WorkingRoot to ensure a clean environment (root is kept so logs/CSV can be written).
  Default: true
  Caution: This removes old working folders before the run begins; ensure important artifacts are archived externally.
- PurgeTestingOnStart (bool)
  Purpose: On start, delete all subfolders inside TestingRoot. Mirrors PurgeWorkingOnStart behavior for the testing folder.
  Default: false

Additional Input Sources (outside JSON)
- AZInfo.csv (optional file next to the script)
  Purpose: Supplies TenantId, ClientId, ClientSecret, CertificateThumbprint (first row only; headers are case-insensitive). Precedence with other sources: CLI parameters > Config.AzureAuth > AZInfo.csv. If both ClientSecret and CertificateThumbprint are present, ClientSecret is used.
  Sample (ClientSecret):
    TenantId,ClientId,ClientSecret,CertificateThumbprint
    00000000-0000-0000-0000-000000000000,11111111-1111-1111-1111-111111111111,"<client-secret>",
  Sample (Certificate):
    TenantId,ClientId,ClientSecret,CertificateThumbprint
    00000000-0000-0000-0000-000000000000,11111111-1111-1111-1111-111111111111,,ABCDEF1234567890ABCDEF1234567890ABCDEF12

- Environment Variables
  SENDGRID_API_KEY (or custom via Email.Smtp.ApiKeyEnv)
  Purpose: Supplies the SMTP API key; never stored in the JSON. The script converts it to a SecureString and uses it for authenticated SMTP.

Behavior Notes
- Default Run Modes:
  - PackageOnly (no -FullRun and no -PackageOnly) is the default: packages one selected recipe; prompts to select a recipe when none specified; wraps into .intunewin; does not upload to Intune.
  - FullRun: downloads, wraps, uploads content, and updates metadata; can process all recipes via AllRecipes=true or single selection.
  - DryRun: only compares Winget vs Intune versions; no download/wrap/upload.
- Command Lines:
  - UseScriptCommandLines=true sets Intune install/uninstall to:
      powershell.exe -ExecutionPolicy Bypass -File "install.ps1"
      powershell.exe -ExecutionPolicy Bypass -File "uninstall.ps1"
    If false, vendor-provided commands are used.
- Detection:
  - UpdateDetection true triggers generation and update of a multi-source detection script. For MSI, ProductCode is read from the MSI file where possible.
- Verification:
  - Module-based size/version verification attempts to ensure Intune reflects the new content; tolerance is configurable; strict mode can fail the run if not converged.
- Email Provider:
  - When Provider="graph", the script acquires an OAuth token via client_credentials and sends via Graph API (no SMTP relay needed). Requires Email.Graph credentials and a licensed mailbox.
  - When Provider="smtp" (or omitted), the script uses System.Net.Mail with the Smtp object settings.

Quick Defaults Summary (if omitted):
- Paths: WorkingRoot="Working", LogPath="AutoPackager.log", RecipesRoot="Recipes", DefaultIconFolder="Logos", TestingRoot="Testing"
- Paths (ADT scripts): LogFilePathAdmin="C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Apps", LogFilePathUser="C:\ProgramData\Logs\Software"
- Branding.NotificationBrandTitle="Your Company"
- AllowAvailableUninstall=false
- Email: Enabled=true; Provider="smtp"; SendPolicy="updatesOrFailures"; AttachCsv=false; AttachLog=true; Smtp required to send
- PackagingDefaults: PreferArchitecture="x64"; DefaultScope="machine"; WingetSource="winget"; RunMode="PackageOnly"; AllRecipes=false; UpdateDetection=true; UseScriptCommandLines=true
- IntuneUploadVerify: TimeoutSeconds=600; IntervalSeconds=10; SkipVerify=false; StrictVerify=false; SizeTolerancePercent=5
- Notification.Defaults: Enabled=false; TimerMinutes=2; DeferralEnabled=false; DeferralHoursAllowed=24
- SecondaryRequiredApp: DisplayNameSuffix=" - Required Update"; ClearExistingBeforeAssign=true; Deadline=23:59 local
- RequiredUpdateDefaultGroups: PilotDelayDays=1; UATDelayDays=5; GADelayDays=9; FilterType defaults="Include"
- Archive: Enabled=true; RetentionDays=14; KeepVersionsPerApp=3
- Cleanup: PurgeWorkingOnStart=true; PurgeTestingOnStart=false